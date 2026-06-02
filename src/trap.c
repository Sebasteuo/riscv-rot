/* ==========================================================================
 * trap.c - Trap handler
 * ==========================================================================
 *
 * Main request handler for the crypto core. When U-mode does an
 * ecall, the processor traps into M-mode and lands here. We read
 * the command from the shared memory zone and dispatch it.
 *
 * Includes authentication (password check), dictionary attack
 * lockout (locks after too many wrong attempts), session tokens
 * with countdown timers, and all the crypto services: MEASURE,
 * QUOTE, SEAL/UNSEAL, NV counters, ELF validation, and supply
 * chain verification.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#include "trap.h"
#include "uart.h"
#include "pmp.h"
#include "pcr.h"
#include "sha256.h"
#include "secure_storage.h"
#include "aes128.h"
#include "keygen.h"
#include "secret.h"

extern void post_umode_report(void);

/* -------------------------------------------------------------------------
 * Dictionary Attack Lockout state
 *
 * These variables track the authentication state of the system.
 * They live in M-mode memory so U-mode cannot tamper with them.
 *
 * failed_tries: how many wrong passwords in a row. resets to 0
 *   on successful auth. increments on each failure.
 *
 * is_locked: 1 if the system is in lockout mode (too many failures).
 *   when locked, ALL commands are rejected until the cooldown finishes.
 *
 * lockout_remaining: counts down during lockout. when it reaches 0,
 *   the system unlocks and resets failed_tries.
 *
 * is_authenticated: 1 if U-mode has successfully authenticated.
 *   must be 1 before MEASURE or any other service can be used.
 *   resets to 0 if the system locks out.
 * ------------------------------------------------------------------------- */
static uint32_t failed_tries __secret;
static uint32_t is_locked __secret;
static uint32_t lockout_remaining __secret;
static uint32_t is_authenticated __secret;

/*
 * da_silent_mode: when 1, the trap handler suppresses all output.
 * used during lockout countdown so we dont spam the UART with
 * thousands of "[TRAP] Exception caught!" messages.
 * gets cleared when the lockout expires or when a real command
 * is processed after unlock.
 */
static uint32_t da_silent_mode __secret;

/* ACT session state */
static uint32_t session_active __secret;
static uint32_t session_token __secret;
static uint32_t session_ttl __secret;
static uint32_t session_counter __secret;

/* -------------------------------------------------------------------------
 * The "correct" password for the crypto core.
 *
 * In a real system this would be derived from a secret or set during
 * provisioning. For our demo we use a fixed 16-byte value.
 * U-mode has to send exactly these bytes to authenticate.
 * ------------------------------------------------------------------------- */
static const uint8_t correct_password[16] = {
    0x52, 0x6F, 0x6F, 0x74, 0x4F, 0x66, 0x54, 0x72,
    0x75, 0x73, 0x74, 0x46, 0x57, 0x21, 0x21, 0x00
    /* this spells "RootOfTrustFW!!" in ASCII */
};
#define CORRECT_PASSWORD_LEN 16

/* -------------------------------------------------------------------------
 * Read/write CSR values using inline assembly
 * ------------------------------------------------------------------------- */
static uint64_t read_mcause(void)
{
    uint64_t val;
    asm volatile("csrr %0, mcause" : "=r"(val));
    return val;
}

static uint64_t read_mepc(void)
{
    uint64_t val;
    asm volatile("csrr %0, mepc" : "=r"(val));
    return val;
}

static uint64_t read_mtval(void)
{
    uint64_t val;
    asm volatile("csrr %0, mtval" : "=r"(val));
    return val;
}

static void write_mepc(uint64_t val)
{
    asm volatile("csrw mepc, %0" :: "r"(val));
}

/* -------------------------------------------------------------------------
 * check_lockout - handle the lockout timer
 *
 * If the system is locked, this decrements the cooldown counter.
 * When the counter reaches zero, the system unlocks and resets
 * the failed attempts counter so the user can try again.
 *
 * Returns 1 if still locked, 0 if not locked (or just unlocked).
 * ------------------------------------------------------------------------- */
static int check_lockout(volatile uint32_t *shared)
{
    if (!is_locked) return 0;

    if (lockout_remaining > 0) {
        lockout_remaining--;
    }

    if (lockout_remaining == 0) {
        /* cooldown finished, unlock the system */
        is_locked = 0;
        failed_tries = 0;
        is_authenticated = 0;
        da_silent_mode = 0;
        uart_puts("[DA] Lockout period expired, system unlocked\n");
        uart_puts("[DA] Failed attempts counter reset to 0\n");
        return 0;
    }

    /* still locked, only print at start and when almost done to avoid spam */
    if (lockout_remaining == DA_LOCKOUT_CYCLES - 1 || lockout_remaining == 1) {
        uart_puts("[DA] System is LOCKED (");
        uart_put_hex(lockout_remaining);
        uart_puts(" cycles remaining)\n");
    }
    shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_LOCKED;
    return 1;
}

/* -------------------------------------------------------------------------
 * process_auth - handle an authentication attempt
 *
 * Reads the password from the shared DATA area and compares it
 * byte by byte with the correct password. If it matches, the
 * system is marked as authenticated and the failed counter resets.
 * If it does not match, the failed counter increments. If the
 * counter reaches DA_MAX_TRIES, the system enters lockout.
 * ------------------------------------------------------------------------- */
static void process_auth(volatile uint32_t *shared)
{
    uint32_t size = shared[SHARED_OFF_SIZE / 4];
    uint8_t *data = (uint8_t *)(SHARED_BASE + SHARED_OFF_DATA);
    uint32_t i;
    int match;

    uart_puts("[DA] Processing AUTH request\n");
    uart_puts("[DA]   Password length: ");
    uart_put_hex(size);
    uart_puts(" bytes\n");

    /* check if password length matches */
    if (size != CORRECT_PASSWORD_LEN) {
        match = 0;
    } else {
        /* compare byte by byte */
        match = 1;
        for (i = 0; i < CORRECT_PASSWORD_LEN; i++) {
            if (data[i] != correct_password[i]) {
                match = 0;
                break;
            }
        }
    }

    if (match) {
        /* correct password */
        failed_tries = 0;
        is_authenticated = 1;
        uart_puts("[DA] Authentication SUCCESSFUL\n");
        uart_puts("[DA] Failed attempts counter reset to 0\n");
        uart_puts("[DA] Services are now unlocked for this session\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_AUTH_OK;
    } else {
        /* wrong password */
        failed_tries++;
        is_authenticated = 0;

        uart_puts("[DA] Authentication FAILED (wrong password)\n");
        uart_puts("[DA] Failed attempts: ");
        uart_put_hex(failed_tries);
        uart_puts(" / ");
        uart_put_hex(DA_MAX_TRIES);
        uart_puts("\n");

        if (failed_tries >= DA_MAX_TRIES) {
            /* too many failures, enter lockout */
            is_locked = 1;
            lockout_remaining = DA_LOCKOUT_CYCLES;
            da_silent_mode = 1;
            uart_puts("[DA] *** LOCKOUT ACTIVATED ***\n");
            uart_puts("[DA] Too many failed attempts (");
            uart_put_hex(failed_tries);
            uart_puts(")\n");
            uart_puts("[DA] System locked for ");
            uart_put_hex(DA_LOCKOUT_CYCLES);
            uart_puts(" cycles\n");
            uart_puts("[DA] All requests will be rejected until cooldown expires\n");
            shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_LOCKED;
        } else {
            uart_puts("[DA] ");
            uart_put_hex(DA_MAX_TRIES - failed_tries);
            uart_puts(" attempts remaining before lockout\n");
            shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_AUTH_FAIL;
        }
    }
}

/* -------------------------------------------------------------------------
 * process_start_session - create a new session with a countdown timer
 *
 * Only works if the host is already authenticated. Generates a
 * unique 4-byte token and sets the TTL. The token is written to
 * the first 4 bytes of the shared DATA area so the host can read it.
 * ------------------------------------------------------------------------- */
static void process_start_session(volatile uint32_t *shared)
{
    if (!is_authenticated) {
        uart_puts("[ACT] Cannot start session: not authenticated\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_NO_AUTH;
        return;
    }

    /* generate a unique token from the counter */
    session_counter++;
    session_token = session_counter;
    session_ttl = ACT_SESSION_TTL;
    session_active = 1;

    /* write the token to the shared DATA area so host can read it */
    uint8_t *data = (uint8_t *)(SHARED_BASE + SHARED_OFF_DATA);
    data[0] = (session_token >> 24) & 0xFF;
    data[1] = (session_token >> 16) & 0xFF;
    data[2] = (session_token >>  8) & 0xFF;
    data[3] = (session_token >>  0) & 0xFF;

    uart_puts("[ACT] Session started\n");
    uart_puts("[ACT]   Token: ");
    uart_put_hex(session_token);
    uart_puts("\n");
    uart_puts("[ACT]   TTL: ");
    uart_put_hex(session_ttl);
    uart_puts(" service calls\n");

    shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_SESSION_OK;
}

/* -------------------------------------------------------------------------
 * check_session_token - verify the token and TTL before a service request
 *
 * The host must write the 4-byte session token at the start of
 * the DATA area (before the actual payload). This function reads
 * it and checks if it matches and if the session is still alive.
 *
 * Returns 0 if OK (token valid, TTL decremented).
 * Returns 1 if rejected (bad token, expired, or no session).
 * ------------------------------------------------------------------------- */
static int check_session_token(volatile uint32_t *shared)
{
    if (!session_active) {
        uart_puts("[ACT] No active session, start one first\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_NO_AUTH;
        return 1;
    }

    if (session_ttl == 0) {
        uart_puts("[ACT] Session EXPIRED (TTL reached 0)\n");
        uart_puts("[ACT] Must re-authenticate and start new session\n");
        session_active = 0;
        is_authenticated = 0;
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_SESSION_EXPIRED;
        return 1;
    }

    /* read the token from the first 4 bytes of DATA */
    uint8_t *data = (uint8_t *)(SHARED_BASE + SHARED_OFF_DATA);
    uint32_t provided_token = ((uint32_t)data[0] << 24)
                            | ((uint32_t)data[1] << 16)
                            | ((uint32_t)data[2] <<  8)
                            | ((uint32_t)data[3] <<  0);

    if (provided_token != session_token) {
        uart_puts("[ACT] Bad session token: ");
        uart_put_hex(provided_token);
        uart_puts(" (expected ");
        uart_put_hex(session_token);
        uart_puts(")\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_BAD_TOKEN;
        return 1;
    }

    /* token is valid, decrement TTL */
    session_ttl--;
    uart_puts("[ACT] Token valid, TTL remaining: ");
    uart_put_hex(session_ttl);
    uart_puts("\n");

    return 0;
}

/* -------------------------------------------------------------------------
 * process_shared_command - handle a request from the shared memory zone
 *
 * Now with authentication and lockout checks:
 * process_nv_read - read the current monotonic counter value
 *
 * Reads the 4-byte counter from Secure Storage slot 5 and writes
 * it to the shared DATA area (after the session token at bytes 0-3).
 * The counter value goes in bytes 4-7 of DATA.
 * ------------------------------------------------------------------------- */
static void process_nv_read(volatile uint32_t *shared)
{
    uint8_t counter_bytes[4] = {0, 0, 0, 0};
    uint32_t read_size = 4;
    uint8_t *data = (uint8_t *)(SHARED_BASE + SHARED_OFF_DATA);

    /* read the counter from Secure Storage slot 5 */
    ss_read_key(NV_COUNTER_SLOT, counter_bytes, &read_size);

    uint32_t counter = ((uint32_t)counter_bytes[0] << 24)
                     | ((uint32_t)counter_bytes[1] << 16)
                     | ((uint32_t)counter_bytes[2] <<  8)
                     | ((uint32_t)counter_bytes[3]);

    /* write counter to DATA bytes 4-7 (after token) */
    data[4] = counter_bytes[0];
    data[5] = counter_bytes[1];
    data[6] = counter_bytes[2];
    data[7] = counter_bytes[3];

    uart_puts("[NVC] Current counter value: ");
    uart_put_hex(counter);
    uart_puts("\n");

    shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_OK;
}

/* -------------------------------------------------------------------------
 * process_nv_increment - increment the monotonic counter
 *
 * The host sends a 4-byte "minimum expected version" in DATA
 * bytes 4-7 (after the token). The crypto core reads the current
 * counter, checks that the expected version is not lower than the
 * counter (anti-rollback check), then sets counter = current + 1.
 *
 * If the expected version is lower than the stored counter, the
 * request is rejected with ROLLBACK status. This catches attempts
 * to load old firmware versions.
 * ------------------------------------------------------------------------- */
static void process_nv_increment(volatile uint32_t *shared)
{
    uint8_t *data = (uint8_t *)(SHARED_BASE + SHARED_OFF_DATA);
    uint8_t counter_bytes[4] = {0, 0, 0, 0};

    /* read expected minimum version from DATA bytes 4-7 */
    uint32_t expected = ((uint32_t)data[4] << 24)
                      | ((uint32_t)data[5] << 16)
                      | ((uint32_t)data[6] <<  8)
                      | ((uint32_t)data[7]);

    /* read current counter from Secure Storage */
    uint32_t read_size = 4;
    ss_read_key(NV_COUNTER_SLOT, counter_bytes, &read_size);
    uint32_t current = ((uint32_t)counter_bytes[0] << 24)
                     | ((uint32_t)counter_bytes[1] << 16)
                     | ((uint32_t)counter_bytes[2] <<  8)
                     | ((uint32_t)counter_bytes[3]);

    uart_puts("[NVC] Increment request\n");
    uart_puts("[NVC]   Current counter: ");
    uart_put_hex(current);
    uart_puts("\n");
    uart_puts("[NVC]   Expected minimum version: ");
    uart_put_hex(expected);
    uart_puts("\n");

    /* anti-rollback: reject if expected version is older than counter */
    if (expected < current) {
        uart_puts("[NVC] *** ROLLBACK DETECTED ***\n");
        uart_puts("[NVC] Expected version ");
        uart_put_hex(expected);
        uart_puts(" is older than counter ");
        uart_put_hex(current);
        uart_puts("\n");
        uart_puts("[NVC] Firmware downgrade REJECTED\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_ROLLBACK;
        return;
    }

    /* increment: new_counter = current + 1 */
    uint32_t new_counter = current + 1;
    counter_bytes[0] = (new_counter >> 24) & 0xFF;
    counter_bytes[1] = (new_counter >> 16) & 0xFF;
    counter_bytes[2] = (new_counter >>  8) & 0xFF;
    counter_bytes[3] = (new_counter >>  0) & 0xFF;

    ss_write_key(NV_COUNTER_SLOT, counter_bytes, 4);

    uart_puts("[NVC] Counter incremented: ");
    uart_put_hex(current);
    uart_puts(" -> ");
    uart_put_hex(new_counter);
    uart_puts("\n");

    /* write new counter to DATA bytes 4-7 so host can read it back */
    data[4] = counter_bytes[0];
    data[5] = counter_bytes[1];
    data[6] = counter_bytes[2];
    data[7] = counter_bytes[3];

    shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_OK;
}

/* -------------------------------------------------------------------------
 * process_shared_command - handle a request from the shared memory zone
 *
 *   1. First check if the system is locked (too many failed auths)
 *   2. AUTH command is always processed (even during lockout check)
 *   3. All other commands require authentication first
 * ------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------
 * compute_pcr_policy - hash all PCR values into a single 32-byte digest
 *
 * Concatenates PCR0 + PCR1 + PCR2 (96 bytes total) and hashes
 * them with SHA-256 to produce a 32-byte policy value.
 * This is the "snapshot" of the platform state at a given moment.
 * ------------------------------------------------------------------------- */
static void compute_pcr_policy(uint8_t policy[SHA256_DIGEST_SIZE])
{
    uint8_t pcr_concat[PCR_COUNT * SHA256_DIGEST_SIZE];
    int i;
    for (i = 0; i < PCR_COUNT; i++) {
        pcr_read(i, &pcr_concat[i * SHA256_DIGEST_SIZE]);
    }
    sha256(pcr_concat, PCR_COUNT * SHA256_DIGEST_SIZE, policy);
}

/* -------------------------------------------------------------------------
 * process_seal - seal data to the current PCR state
 *
 * Reads the payload from DATA (after the 4-byte token), stores
 * it in Secure Storage slot 6. Then computes the PCR policy
 * hash and stores it in slot 7. Both must succeed for the seal
 * to be considered valid.
 * ------------------------------------------------------------------------- */
static void process_seal(volatile uint32_t *shared)
{
    uint32_t size = shared[SHARED_OFF_SIZE / 4];
    uint8_t *data = (uint8_t *)(SHARED_BASE + SHARED_OFF_DATA);
    uint8_t policy[SHA256_DIGEST_SIZE];
    uint8_t padded[32];
    uint8_t encrypted[32];
    uint32_t payload_size;
    uint32_t enc_size;
    int i;
    aes128_context aes;

    if (size <= 4) {
        uart_puts("[SEAL] ERROR: no data to seal\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_ERROR;
        return;
    }
    payload_size = size - 4;
    if (payload_size > 32) {
        uart_puts("[SEAL] ERROR: data too large (max 32 bytes)\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_ERROR;
        return;
    }

    uart_puts("[SEAL] Sealing ");
    uart_put_hex(payload_size);
    uart_puts(" bytes with AES-128 encryption\n");

    /* compute PCR policy hash, first 16 bytes become AES key */
    compute_pcr_policy(policy);
    aes128_init(&aes, policy);
    uart_puts("[SEAL] AES key derived from PCR policy\n");

    /* zero-pad payload to multiple of 16 bytes */
    for (i = 0; i < 32; i++) padded[i] = 0;
    for (i = 0; i < (int)payload_size; i++) padded[i] = data[4 + i];
    enc_size = ((payload_size + 15) / 16) * 16;

    /* encrypt with AES-128 ECB */
    aes128_encrypt(&aes, padded, encrypted, enc_size);

    uart_puts("[SEAL] Ciphertext: ");
    for (i = 0; i < 4; i++) { uart_put_hex(encrypted[i]); uart_puts(" "); }
    uart_puts("...\n");

    /* store encrypted data and policy */
    ss_write_key(SEAL_DATA_SLOT, encrypted, enc_size);
    ss_write_key(SEAL_POLICY_SLOT, policy, SHA256_DIGEST_SIZE);

    uart_puts("[SEAL] Encrypted data in slot ");
    uart_put_hex(SEAL_DATA_SLOT);
    uart_puts(", policy in slot ");
    uart_put_hex(SEAL_POLICY_SLOT);
    uart_puts("\n");

    shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_OK;
}
/* -------------------------------------------------------------------------
 * process_unseal - unseal data if current PCRs match the stored policy
 *
 * Recomputes the PCR policy hash and compares it byte-by-byte
 * with the stored policy in slot 7. If they match, the sealed
 * data from slot 6 is copied to the shared DATA area (after token).
 * If they dont match, the data stays locked.
 * ------------------------------------------------------------------------- */
static void process_unseal(volatile uint32_t *shared)
{
    uint8_t current_policy[SHA256_DIGEST_SIZE];
    uint8_t stored_policy[SHA256_DIGEST_SIZE];
    uint8_t encrypted_data[32];
    uint8_t decrypted[32];
    uint32_t policy_size = SHA256_DIGEST_SIZE;
    uint32_t data_size = 32;
    uint8_t *data = (uint8_t *)(SHARED_BASE + SHARED_OFF_DATA);
    int i, match;
    aes128_context aes;

    if (!ss_key_exists(SEAL_DATA_SLOT) || !ss_key_exists(SEAL_POLICY_SLOT)) {
        uart_puts("[SEAL] ERROR: nothing sealed yet\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_NOT_SEALED;
        return;
    }

    uart_puts("[SEAL] Unseal request, checking PCR policy...\n");
    compute_pcr_policy(current_policy);
    ss_read_key(SEAL_POLICY_SLOT, stored_policy, &policy_size);

    match = 1;
    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        if (current_policy[i] != stored_policy[i]) { match = 0; break; }
    }

    if (!match) {
        uart_puts("[SEAL] *** PCR MISMATCH ***\n");
        uart_puts("[SEAL] Cannot derive correct AES key, data stays encrypted\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_PCR_MISMATCH;
        return;
    }

    /* derive same AES key from matching policy */
    aes128_init(&aes, current_policy);
    ss_read_key(SEAL_DATA_SLOT, encrypted_data, &data_size);

    uint32_t dec_size = ((data_size + 15) / 16) * 16;
    aes128_decrypt(&aes, encrypted_data, decrypted, dec_size);

    uart_puts("[SEAL] PCR policy matches, data decrypted with AES-128\n");
    uart_puts("[SEAL] Plaintext recovered (");
    uart_put_hex(data_size);
    uart_puts(" bytes)\n");

    for (i = 0; i < (int)data_size; i++) {
        data[4 + i] = decrypted[i];
    }

    shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_OK;
}

/* -------------------------------------------------------------------------
 * ELF header whitelist and validation
 *
 * The whitelist stores golden SHA-256 hashes of approved binary
 * sections. During measured launch, the host sends each section
 * to the crypto core, which hashes it and checks against the list.
 *
 * This is similar to IMA (Integrity Measurement Architecture) in
 * Linux, but running at the firmware level before any OS loads.
 * Reference: Sailer et al., USENIX Security 2004.
 * ------------------------------------------------------------------------- */
static uint8_t elf_whitelist[ELF_WHITELIST_MAX][SHA256_DIGEST_SIZE] __secret;
static uint32_t elf_whitelist_count __secret;

/* -------------------------------------------------------------------------
 * process_elf_validate - check if an ELF header is valid RISC-V 64-bit
 *
 * The ELF header is 64 bytes for ELF64. We check:
 *   - Magic number: 0x7f 'E' 'L' 'F'
 *   - Class: 2 (64-bit)
 *   - Data: 1 (little-endian)
 *   - Machine: 0xF3 (RISC-V)
 *
 * If all checks pass, this binary is a valid RISC-V ELF and can
 * proceed to section-by-section measurement.
 * ------------------------------------------------------------------------- */
static void process_elf_validate(volatile uint32_t *shared)
{
    uint32_t size = shared[SHARED_OFF_SIZE / 4];
    uint8_t *data = (uint8_t *)(SHARED_BASE + SHARED_OFF_DATA);

    /* need at least token (4) + ELF header (64) = 68 bytes */
    if (size < 68) {
        uart_puts("[ELF] ERROR: data too small for ELF header\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_BAD_ELF;
        return;
    }

    uint8_t *elf = &data[4];  /* skip session token */

    uart_puts("[ELF] Validating ELF header...\n");

    /* check magic number: 0x7f 'E' 'L' 'F' */
    if (elf[0] != 0x7f || elf[1] != 'E' || elf[2] != 'L' || elf[3] != 'F') {
        uart_puts("[ELF] *** INVALID MAGIC NUMBER ***\n");
        uart_puts("[ELF] Expected: 7f 45 4c 46, got: ");
        uart_put_hex(elf[0]); uart_puts(" ");
        uart_put_hex(elf[1]); uart_puts(" ");
        uart_put_hex(elf[2]); uart_puts(" ");
        uart_put_hex(elf[3]); uart_puts("\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_BAD_ELF;
        return;
    }
    uart_puts("[ELF] Magic number: OK (7f 45 4c 46)\n");

    /* check class: must be 2 (ELF64) */
    if (elf[4] != 2) {
        uart_puts("[ELF] *** WRONG CLASS ***\n");
        uart_puts("[ELF] Expected: 2 (64-bit), got: ");
        uart_put_hex(elf[4]); uart_puts("\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_BAD_ELF;
        return;
    }
    uart_puts("[ELF] Class: ELF64 (64-bit)\n");

    /* check data encoding: must be 1 (little-endian) */
    if (elf[5] != 1) {
        uart_puts("[ELF] *** WRONG ENDIANNESS ***\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_BAD_ELF;
        return;
    }
    uart_puts("[ELF] Endianness: little-endian\n");

    /* check machine: must be 0xF3 (RISC-V) at offset 18 (LE 16-bit) */
    uint16_t machine = (uint16_t)elf[18] | ((uint16_t)elf[19] << 8);
    if (machine != 0xF3) {
        uart_puts("[ELF] *** WRONG ARCHITECTURE ***\n");
        uart_puts("[ELF] Expected: 0xf3 (RISC-V), got: ");
        uart_put_hex(machine); uart_puts("\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_BAD_ELF;
        return;
    }
    uart_puts("[ELF] Architecture: RISC-V (0xf3)\n");

    uart_puts("[ELF] ELF header validation PASSED\n");
    shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_ELF_OK;
}

/* -------------------------------------------------------------------------
 * process_elf_register - add a golden hash to the whitelist
 *
 * The host sends a 32-byte SHA-256 hash (after the token) that
 * represents a known-good section. Up to ELF_WHITELIST_MAX entries.
 * ------------------------------------------------------------------------- */
static void process_elf_register(volatile uint32_t *shared)
{
    uint32_t size = shared[SHARED_OFF_SIZE / 4];
    uint8_t *data = (uint8_t *)(SHARED_BASE + SHARED_OFF_DATA);
    int i;

    if (size < 4 + SHA256_DIGEST_SIZE) {
        uart_puts("[ELF] ERROR: need 32-byte hash to register\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_ERROR;
        return;
    }

    if (elf_whitelist_count >= ELF_WHITELIST_MAX) {
        uart_puts("[ELF] Whitelist is full\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_WL_FULL;
        return;
    }

    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        elf_whitelist[elf_whitelist_count][i] = data[4 + i];
    }
    uart_puts("[ELF] Registered golden hash #");
    uart_put_hex(elf_whitelist_count);
    uart_puts(": ");
    uart_put_hex(data[4]); uart_puts(" ");
    uart_put_hex(data[5]); uart_puts(" ");
    uart_put_hex(data[6]); uart_puts(" ");
    uart_put_hex(data[7]); uart_puts(" ...\n");

    elf_whitelist_count++;
    shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_WL_REGISTERED;
}

/* -------------------------------------------------------------------------
 * process_elf_check_hash - hash a section and check against whitelist
 *
 * The host sends a binary section (after the token). The crypto
 * core computes SHA-256 and compares against all registered hashes.
 * If it matches any entry, the section is approved for loading.
 * ------------------------------------------------------------------------- */
static void process_elf_check_hash(volatile uint32_t *shared)
{
    uint32_t size = shared[SHARED_OFF_SIZE / 4];
    uint8_t *data = (uint8_t *)(SHARED_BASE + SHARED_OFF_DATA);
    uint8_t hash[SHA256_DIGEST_SIZE];
    uint32_t payload_size;
    uint32_t i, j;
    int match;

    if (size <= 4) {
        uart_puts("[ELF] ERROR: no section data to check\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_ERROR;
        return;
    }
    payload_size = size - 4;

    /* hash the section */
    sha256(&data[4], payload_size, hash);

    uart_puts("[ELF] Section hash: ");
    uart_put_hex(hash[0]); uart_puts(" ");
    uart_put_hex(hash[1]); uart_puts(" ");
    uart_put_hex(hash[2]); uart_puts(" ");
    uart_put_hex(hash[3]); uart_puts(" ...\n");

    /* compare against whitelist */
    for (i = 0; i < elf_whitelist_count; i++) {
        match = 1;
        for (j = 0; j < SHA256_DIGEST_SIZE; j++) {
            if (hash[j] != elf_whitelist[i][j]) {
                match = 0;
                break;
            }
        }
        if (match) {
            uart_puts("[ELF] MATCH with whitelist entry #");
            uart_put_hex(i);
            uart_puts("\n");
            uart_puts("[ELF] Section APPROVED for loading\n");
            shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_HASH_MATCH;
            return;
        }
    }

    uart_puts("[ELF] *** NO MATCH in whitelist ***\n");
    uart_puts("[ELF] Section REJECTED (unknown binary)\n");
    shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_HASH_REJECT;
}


/* -------------------------------------------------------------------------
 * Supply Chain vendor table
 *
 * Each vendor has an ID (0-255) and a 16-byte symmetric key.
 * In a real system these would be asymmetric public keys burned
 * during manufacturing. For our demo, symmetric HMAC keys work
 * the same way conceptually.
 *
 * Based on NIST SP 800-193 (Platform Firmware Resiliency).
 * ------------------------------------------------------------------------- */
static struct {
    uint8_t id;
    uint8_t key[16];
    uint8_t active;
} chain_vendors[CHAIN_MAX_VENDORS] __secret;
static uint32_t chain_vendor_count __secret;

/* -------------------------------------------------------------------------
 * process_chain_add_vendor - register a vendor key
 *
 * DATA layout (after 4-byte token):
 *   byte 0: vendor ID (0-255)
 *   bytes 1-16: vendor key (16 bytes)
 * Total: 4 token + 1 ID + 16 key = 21 bytes minimum
 * ------------------------------------------------------------------------- */
static void process_chain_add_vendor(volatile uint32_t *shared)
{
    uint32_t size = shared[SHARED_OFF_SIZE / 4];
    uint8_t *data = (uint8_t *)(SHARED_BASE + SHARED_OFF_DATA);
    int i;

    if (size < 21) {
        uart_puts("[CHAIN] ERROR: need vendor ID (1) + key (16)\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_ERROR;
        return;
    }

    if (chain_vendor_count >= CHAIN_MAX_VENDORS) {
        uart_puts("[CHAIN] Vendor table is full\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_VENDORS_FULL;
        return;
    }

    uint8_t vendor_id = data[4];
    chain_vendors[chain_vendor_count].id = vendor_id;
    chain_vendors[chain_vendor_count].active = 1;
    for (i = 0; i < 16; i++) {
        chain_vendors[chain_vendor_count].key[i] = data[5 + i];
    }

    uart_puts("[CHAIN] Registered vendor 0x");
    uart_put_hex(vendor_id);
    uart_puts(" with key: ");
    uart_put_hex(data[5]); uart_puts(" ");
    uart_put_hex(data[6]); uart_puts(" ");
    uart_put_hex(data[7]); uart_puts(" ");
    uart_put_hex(data[8]); uart_puts(" ...\n");

    chain_vendor_count++;
    shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_VENDOR_OK;
}

/* -------------------------------------------------------------------------
 * process_chain_verify - verify a signed component
 *
 * DATA layout (after 4-byte token):
 *   byte 0: vendor ID
 *   bytes 1-32: HMAC-SHA256 signature (32 bytes)
 *   bytes 33+: payload (the component binary)
 *
 * The crypto core looks up the vendor key, computes
 * HMAC-SHA256(vendor_key, payload), and compares with the
 * provided signature. If they match, the component is authentic
 * and came from the claimed vendor.
 * ------------------------------------------------------------------------- */
static void process_chain_verify(volatile uint32_t *shared)
{
    uint32_t size = shared[SHARED_OFF_SIZE / 4];
    uint8_t *data = (uint8_t *)(SHARED_BASE + SHARED_OFF_DATA);
    uint8_t expected_sig[SHA256_DIGEST_SIZE];
    int i, found;
    uint8_t *vendor_key = 0;

    /* minimum: 4 token + 1 ID + 32 signature + 1 payload = 38 */
    if (size < 38) {
        uart_puts("[CHAIN] ERROR: data too small\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_ERROR;
        return;
    }

    uint8_t vendor_id = data[4];
    uint8_t *provided_sig = &data[5];
    uint8_t *payload = &data[37];
    uint32_t payload_size = size - 37;

    uart_puts("[CHAIN] Verifying component from vendor 0x");
    uart_put_hex(vendor_id);
    uart_puts(" (");
    uart_put_hex(payload_size);
    uart_puts(" bytes)\n");

    /* find vendor key */
    found = 0;
    for (i = 0; i < (int)chain_vendor_count; i++) {
        if (chain_vendors[i].active && chain_vendors[i].id == vendor_id) {
            vendor_key = chain_vendors[i].key;
            found = 1;
            break;
        }
    }

    if (!found) {
        uart_puts("[CHAIN] *** UNKNOWN VENDOR ***\n");
        uart_puts("[CHAIN] Vendor 0x");
        uart_put_hex(vendor_id);
        uart_puts(" is not registered\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_UNKNOWN_VENDOR;
        return;
    }

    /* compute HMAC-SHA256(vendor_key, payload) */
    hmac_sha256(vendor_key, 16, payload, payload_size, expected_sig);

    /* compare with provided signature */
    int match = 1;
    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        if (expected_sig[i] != provided_sig[i]) {
            match = 0;
            break;
        }
    }

    if (match) {
        uart_puts("[CHAIN] Signature VALID\n");
        uart_puts("[CHAIN] Component authenticated from vendor 0x");
        uart_put_hex(vendor_id);
        uart_puts("\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_CHAIN_OK;
    } else {
        uart_puts("[CHAIN] *** SIGNATURE MISMATCH ***\n");
        uart_puts("[CHAIN] Component may be TAMPERED or from wrong vendor\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_CHAIN_FAIL;
    }
}

static void process_shared_command(void)
{
    volatile uint32_t *shared = (volatile uint32_t *)SHARED_BASE;
    uint32_t cmd      = shared[SHARED_OFF_CMD / 4];
    uint32_t size     = shared[SHARED_OFF_SIZE / 4];
    uint32_t pcr_idx  = shared[SHARED_OFF_PCR_IDX / 4];
    uint8_t *data     = (uint8_t *)(SHARED_BASE + SHARED_OFF_DATA);
    uint32_t max_data = SHARED_SIZE - SHARED_OFF_DATA;

    /*
     * Measure command processing time using the mcycle CSR.
     * We read the cycle counter before and after processing,
     * then print the difference. This satisfies SRS-P-002
     * (command response time <= 100ms).
     */
    uint64_t cmd_start, cmd_end;
    asm volatile("csrr %0, mcycle" : "=r"(cmd_start));

    /*
     * Step 1: Handle AUTH command separately
     * AUTH is the only command that can be processed even when
     * not yet authenticated. But if locked, even AUTH is rejected.
     */
    if (cmd == SHARED_CMD_AUTH) {
        if (check_lockout(shared)) return;  /* locked, reject */
        process_auth(shared);
        return;
    }

    /*
     * Step 1b: Handle START_SESSION (requires auth but not a session yet)
     */
    if (cmd == SHARED_CMD_START_SESSION) {
        if (check_lockout(shared)) return;
        if (!is_authenticated) {
            uart_puts("[ACT] Must authenticate before starting session\n");
            shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_NO_AUTH;
            return;
        }
        process_start_session(shared);
        return;
    }

    /*
     * Step 2: For all other commands, check lockout and auth
     */
    if (check_lockout(shared)) return;  /* locked, reject */

    if (!is_authenticated) {
        uart_puts("[DA] Request rejected: not authenticated\n");
        uart_puts("[DA] Send SHARED_CMD_AUTH with correct password first\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_NO_AUTH;
        return;
    }

    /*
     * Step 3: Process the actual command (authenticated and not locked)
     */
    switch (cmd) {
    case SHARED_CMD_MEASURE:
        /* check session token (first 4 bytes of DATA) */
        if (check_session_token(shared)) return;

        /* adjust data pointer and size: skip the 4-byte token */
        data = (uint8_t *)(SHARED_BASE + SHARED_OFF_DATA + 4);
        size = shared[SHARED_OFF_SIZE / 4];
        if (size <= 4) {
            uart_puts("[CORE] ERROR: data too small (need token + payload)\n");
            shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_ERROR;
            return;
        }
        size -= 4;  /* subtract token bytes from total size */

        if (size == 0 || size > max_data - 4) {
            uart_puts("[CORE] ERROR: invalid data size\n");
            shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_ERROR;
            return;
        }
        if (pcr_idx >= PCR_COUNT) {
            uart_puts("[CORE] ERROR: invalid PCR index\n");
            shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_ERROR;
            return;
        }

        uart_puts("[CORE] Processing MEASURE command\n");
        uart_puts("[CORE]   Data size: ");
        uart_put_hex(size);
        uart_puts(" bytes, target PCR: ");
        uart_put_hex(pcr_idx);
        uart_puts("\n");

        pcr_measure_and_extend(pcr_idx, data, size);

        uart_puts("[CORE] Measurement complete\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_OK;
        break;

    case SHARED_CMD_NV_READ:
        /* reading the counter also requires a valid session */
        if (check_session_token(shared)) return;
        process_nv_read(shared);
        break;

    case SHARED_CMD_NV_INCREMENT:
        /* incrementing the counter requires a valid session */
        if (check_session_token(shared)) return;
        process_nv_increment(shared);
        break;

    case SHARED_CMD_SEAL:
        if (check_session_token(shared)) return;
        process_seal(shared);
        break;

    case SHARED_CMD_UNSEAL:
        if (check_session_token(shared)) return;
        process_unseal(shared);
        break;

    case SHARED_CMD_ELF_VALIDATE:
        if (check_session_token(shared)) return;
        process_elf_validate(shared);
        break;

    case SHARED_CMD_ELF_REGISTER:
        if (check_session_token(shared)) return;
        process_elf_register(shared);
        break;

    case SHARED_CMD_ELF_CHECK_HASH:
        if (check_session_token(shared)) return;
        process_elf_check_hash(shared);
        break;

    case SHARED_CMD_CHAIN_ADD_VENDOR:
        if (check_session_token(shared)) return;
        process_chain_add_vendor(shared);
        break;

    case SHARED_CMD_CHAIN_VERIFY:
        if (check_session_token(shared)) return;
        process_chain_verify(shared);
        break;

    case SHARED_CMD_QUOTE:
        /* -------------------------------------------------------
         * TPM2_Quote simplified
         *
         * Produces a signed attestation of the current PCR values.
         * The crypto core concatenates all 3 PCRs (96 bytes),
         * then computes HMAC-SHA256 over them using the EK as key.
         * The result is a 32-byte signature that a remote verifier
         * can check if they know the EK.
         *
         * Layout in shared DATA (after 4-byte session token):
         *   bytes 4-35:   PCR0 value (32 bytes)
         *   bytes 36-67:  PCR1 value (32 bytes)
         *   bytes 68-99:  PCR2 value (32 bytes)
         *   bytes 100-131: HMAC signature (32 bytes)
         * Total: 132 bytes written to DATA area
         * ------------------------------------------------------- */
        if (check_session_token(shared)) return;

        uart_puts("[QUOTE] Generating PCR attestation quote\n");
        {
            uint8_t pcr_concat[96];  /* 3 PCRs x 32 bytes */
            uint8_t ek_key[32];
            uint32_t ek_size = 32;
            uint8_t signature[32];
            uint8_t *out = (uint8_t *)(SHARED_BASE + SHARED_OFF_DATA + 4);
            int qi;

            /* read all 3 PCR values into a single buffer */
            for (qi = 0; qi < PCR_COUNT; qi++) {
                pcr_read(qi, &pcr_concat[qi * 32]);
            }

            /* read the EK from Secure Storage */
            ss_read_key(KEY_ID_EK, ek_key, &ek_size);

            /* sign the PCR concatenation with HMAC-SHA256(EK, PCRs) */
            hmac_sha256(ek_key, 32, pcr_concat, 96, signature);

            uart_puts("[QUOTE] PCR values concatenated (96 bytes)\n");
            uart_puts("[QUOTE] Signed with EK using HMAC-SHA256\n");
            uart_puts("[QUOTE] Signature: ");
            for (qi = 0; qi < 8; qi++) {
                uart_put_hex(signature[qi]);
                uart_puts(" ");
            }
            uart_puts("...\n");

            /* write PCRs + signature to shared DATA */
            for (qi = 0; qi < 96; qi++) {
                out[qi] = pcr_concat[qi];
            }
            for (qi = 0; qi < 32; qi++) {
                out[96 + qi] = signature[qi];
            }
        }

        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_OK;
        break;

    default:
        uart_puts("[CORE] ERROR: unknown command ");
        uart_put_hex(cmd);
        uart_puts("\n");
        shared[SHARED_OFF_STATUS / 4] = SHARED_STATUS_ERROR;
        break;
    }

    /* print command processing time */
    asm volatile("csrr %0, mcycle" : "=r"(cmd_end));
    uart_puts("[PERF] Command ");
    uart_put_hex(cmd);
    uart_puts(" processed in ");
    uart_put_hex((uint32_t)(cmd_end - cmd_start));
    uart_puts(" cycles\n");
}

/* -------------------------------------------------------------------------
 * trap_handler - main exception handler called from trap_entry.S
 * ------------------------------------------------------------------------- */
void trap_handler(void)
{
    uint64_t mcause = read_mcause();
    uint64_t mepc = read_mepc();
    uint64_t mtval = read_mtval();

    /*
     * In silent mode (during lockout countdown), skip all output
     * and just process the ecall to tick the lockout counter.
     * This avoids flooding the UART with thousands of trap messages.
     */
    if (da_silent_mode && mcause == CAUSE_ECALL_U) {
        volatile uint32_t *sh = (volatile uint32_t *)SHARED_BASE;
        uint32_t cmd = sh[SHARED_OFF_CMD / 4];
        if (cmd != SHARED_CMD_NONE) {
            process_shared_command();
            sh[SHARED_OFF_CMD / 4] = SHARED_CMD_NONE;
        }
        write_mepc(mepc + 4);
        return;
    }

    uart_puts("\n[TRAP] ============================\n");
    uart_puts("[TRAP] Exception caught!\n");
    uart_puts("[TRAP] mcause = ");
    uart_put_hex(mcause);
    uart_puts("\n");
    uart_puts("[TRAP] mepc   = ");
    uart_put_hex(mepc);
    uart_puts("\n");
    uart_puts("[TRAP] mtval  = ");
    uart_put_hex(mtval);
    uart_puts("\n");

    switch (mcause) {
    case CAUSE_LOAD_ACCESS:
        uart_puts("[TRAP] >> LOAD ACCESS FAULT\n");
        uart_puts("[TRAP] >> U-mode tried to READ from a protected address\n");
        uart_puts("[TRAP] >> PMP blocked it, secret is safe\n");
        break;

    case CAUSE_STORE_ACCESS:
        uart_puts("[TRAP] >> STORE ACCESS FAULT\n");
        uart_puts("[TRAP] >> U-mode tried to WRITE to a protected address\n");
        uart_puts("[TRAP] >> PMP blocked it, secret is safe\n");
        break;

    case CAUSE_FETCH_ACCESS:
        uart_puts("[TRAP] >> INSTRUCTION ACCESS FAULT\n");
        break;

    case CAUSE_ILLEGAL_INST:
        uart_puts("[TRAP] >> ILLEGAL INSTRUCTION\n");
        break;

    case CAUSE_ECALL_U:
        uart_puts("[TRAP] >> ECALL from U-mode\n");

        {
            volatile uint32_t *shared = (volatile uint32_t *)SHARED_BASE;
            uint32_t cmd = shared[SHARED_OFF_CMD / 4];

            if (cmd != SHARED_CMD_NONE) {
                process_shared_command();
                shared[SHARED_OFF_CMD / 4] = SHARED_CMD_NONE;
            } else {
                uart_puts("[TRAP] >> U-mode finished, generating final report\n");
                post_umode_report();
            }
        }
        break;

    default:
        uart_puts("[TRAP] >> Unknown exception\n");
        break;
    }

    uart_puts("[TRAP] ============================\n");

    write_mepc(mepc + 4);
}

/* -------------------------------------------------------------------------
 * trap_install - set up the trap handler
 * ------------------------------------------------------------------------- */
void trap_install(void)
{
    extern void trap_entry(void);

    /* session counter lives in .secret (zeroed at boot), set its start value */
    session_counter = 0x1000;
    uint64_t addr = (uint64_t)(uintptr_t)trap_entry;

    addr &= ~0x3UL;
    asm volatile("csrw mtvec, %0" :: "r"(addr));

    uart_puts("[TRAP] Trap handler installed at ");
    uart_put_hex(addr);
    uart_puts("\n");
}
