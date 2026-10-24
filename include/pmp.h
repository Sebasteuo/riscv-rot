/* ==========================================================================
 * pmp.h - Physical Memory Protection (PMP) definitions
 * ==========================================================================
 *
 * PMP is how RISC-V protects memory at the hardware level. From M-mode
 * we set up rules that say which memory regions can be accessed and by
 * whom. When we drop to U-mode, the processor enforces those rules on
 * every memory access.
 *
 * Each 8-bit config has these fields:
 *   bit 0 (R) read, bit 1 (W) write, bit 2 (X) execute
 *   bits 3-4 (A) address matching mode
 *     00=OFF, 01=TOR, 10=NA4, 11=NAPOT
 *   bit 7 (L) lock
 *
 * NAPOT encoding: pmpaddr = (base >> 2) | ((size/2 - 1) >> 2)
 *
 * Added SHARED_BASE for the shared memory zone where U-mode
 * writes data (firmware binaries) for the crypto core to measure.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */
#ifndef PMP_H
#define PMP_H

#include <stdint.h>

/* pmpcfg permission bits */
#define PMP_R       0x01
#define PMP_W       0x02
#define PMP_X       0x04

/* address matching modes */
#define PMP_A_OFF   0x00
#define PMP_A_TOR   0x08
#define PMP_A_NA4   0x10
#define PMP_A_NAPOT 0x18

/* lock bit */
#define PMP_L       0x80

/* -------------------------------------------------------------------------
 * Memory layout
 *
 * 0x10000000  UART (serial port)
 * 0x10200000  Secure Storage MMIO device (inside custom QEMU)
 * 0x80000000  Firmware code (.text, .rodata, .data, .bss, .stack)
 * 0x80200000  Secret zone (4KB, crypto keys in RAM)
 * 0x80200000  U-mode code
 * 0x80300000  Shared memory zone (4KB, U-mode writes, M-mode reads)
 *
 * The shared zone is the mailbox between host (U-mode) and crypto
 * core (M-mode). U-mode puts data there and uses ecall to ask the
 * core to process it. The core reads from there, hashes it, and
 * extends the result into a PCR.
 * ------------------------------------------------------------------------- */
#define SECRET_BASE  0x80200000UL
#define SECRET_SIZE  0x1000UL       /* 4KB */

#define USER_BASE    0x80200000UL

#define SHARED_BASE  0x80300000UL
#define SHARED_SIZE  0x1000UL       /* 4KB */

/*
 * Shared memory protocol:
 * The first 16 bytes of the shared zone are a header that tells
 * the crypto core what to do and how much data there is.
 *
 * Offset 0x00: command (uint32_t)
 * Offset 0x04: data size in bytes (uint32_t)
 * Offset 0x08: PCR index to extend (uint32_t)
 * Offset 0x0C: status / result (uint32_t, written by M-mode)
 * Offset 0x10: data starts here (up to SHARED_SIZE - 0x10 bytes)
 */
#define SHARED_OFF_CMD       0x00
#define SHARED_OFF_SIZE      0x04
#define SHARED_OFF_PCR_IDX   0x08
#define SHARED_OFF_STATUS    0x0C
#define SHARED_OFF_DATA      0x10

/* commands that U-mode can request */
#define SHARED_CMD_NONE      0x00
#define SHARED_CMD_MEASURE   0x01  /* measure data and extend PCR */
#define SHARED_CMD_QUOTE     0x02  /* sign PCR values with EK (future) */
#define SHARED_CMD_AUTH      0x03  /* authenticate: host must send a password
                                    * before it can use any other service.
                                    * the password goes in the DATA area of
                                    * the shared zone (max 32 bytes).
                                    * if correct: STATUS = AUTH_OK, services unlocked
                                    * if wrong: STATUS = AUTH_FAIL, failed counter goes up
                                    * if locked: STATUS = LOCKED, all requests rejected */

/* -------------------------------------------------------------------------
 * Dictionary Attack Lockout
 *
 * This prevents brute-force password guessing. If someone tries
 * the wrong password too many times in a row, the system locks
 * itself and refuses ALL requests for a cooldown period.
 *
 * Think of it like a phone that locks after too many wrong PINs.
 * The counter resets to zero on a successful authentication.
 *
 * DA_MAX_TRIES: how many wrong attempts before locking (3 means
 *   you get 3 chances, on the 4th wrong try it locks)
 * DA_LOCKOUT_CYCLES: how long the lockout lasts. this is a simple
 *   loop counter, not real time, since we have no clock in bare-metal.
 *   in a real system this would be seconds or minutes.
 * ------------------------------------------------------------------------- */
#define DA_MAX_TRIES         3
#define DA_LOCKOUT_CYCLES    50

/* -------------------------------------------------------------------------
 * Extended status codes for authentication
 *
 * These are returned in the STATUS field of the shared zone
 * so U-mode knows what happened after an auth attempt.
 * ------------------------------------------------------------------------- */
#define SHARED_STATUS_LOCKED    0x03  /* system is locked, too many failed attempts */
#define SHARED_STATUS_AUTH_FAIL 0x04  /* password was wrong */
#define SHARED_STATUS_AUTH_OK   0x05  /* password was correct, services unlocked */
#define SHARED_STATUS_NO_AUTH   0x06  /* not authenticated yet, send AUTH first */

/* max password length in bytes (goes in shared DATA area) */
#define AUTH_PASSWORD_MAX_LEN  32

/* -------------------------------------------------------------------------
 * Authenticated Countdown Timers (ACT)
 *
 * After authenticating, the host can request a session token.
 * The token is valid for a limited number of ecall cycles.
 * Once expired, the host loses access and must re-authenticate.
 *
 * This is like giving a maintenance engineer temporary access, where
 * they get a badge that works for 30 minutes, then it stops
 * working and they have to check in again at the front desk.
 *
 * SHARED_CMD_START_SESSION: host requests a session after auth.
 *   The crypto core generates a 4-byte token and writes it to
 *   the shared DATA area. The token is valid for ACT_SESSION_TTL
 *   ecall cycles.
 *
 * For MEASURE and other service commands, the host must write
 * the session token at the first 4 bytes of DATA before the
 * actual payload. The crypto core checks the token and the
 * remaining TTL before processing the request.
 *
 * ACT_SESSION_TTL: how many ecall cycles the session lasts.
 *   Each service request (not just any ecall) decrements it.
 *   When it hits 0, the session expires.
 * ------------------------------------------------------------------------- */
#define SHARED_CMD_START_SESSION  0x04  /* request a session token after auth */

#define ACT_SESSION_TTL           20    /* session expires after 20 service calls */

#define SHARED_STATUS_SESSION_OK      0x07  /* session created, token in DATA */
#define SHARED_STATUS_SESSION_EXPIRED 0x08  /* session token expired, re-auth needed */
#define SHARED_STATUS_BAD_TOKEN       0x09  /* wrong session token */

/* -------------------------------------------------------------------------
 * Monotonic NV Counters
 *
 * A counter that can only go up, never down. Stored in Secure
 * Storage slot 5 so it survives reboots. used for anti-rollback, where
 * each firmware version has a version number, and if someone tries
 * to load a firmware with a version number lower than the counter,
 * the crypto core rejects it.
 *
 * Think of it like the odometer in a car. It only goes forward.
 * If someone tries to roll it back, you know something is wrong.
 *
 * SHARED_CMD_NV_READ: read the current counter value. The crypto
 *   core writes the 4-byte counter to the shared DATA area.
 *
 * SHARED_CMD_NV_INCREMENT: bump the counter by 1. The host writes
 *   a 4-byte "minimum expected value" in DATA (after the token).
 *   If the stored counter is already higher, the increment still
 *   works (counter = max(current, expected) + 1). This prevents
 *   a replay where someone sends an old increment command.
 *
 * NV_COUNTER_SLOT: which Secure Storage slot holds the counter.
 * ------------------------------------------------------------------------- */
#define SHARED_CMD_NV_READ        0x05  /* read current counter value */
#define SHARED_CMD_NV_INCREMENT   0x06  /* increment the counter */

#define NV_COUNTER_SLOT           5     /* Secure Storage slot for the counter */

#define SHARED_STATUS_ROLLBACK    0x0A  /* version too old, counter is higher */

/* -------------------------------------------------------------------------
 * Sealed Storage
 *
 * Data sealed to the current platform state. The crypto core
 * stores data in a Secure Storage slot along with a "policy"
 * which is the SHA-256 hash of all PCR values at seal time.
 *
 * When unsealing, the crypto core recalculates the PCR hash
 * and compares it with the stored policy. If the firmware has
 * been modified since sealing, the PCRs will be different,
 * the hash wont match, and the data stays locked.
 *
 * Think of it like a safe that only opens if the building
 * security cameras show everything is normal. If someone
 * tampered with the cameras (firmware), the safe stays shut.
 *
 * SHARED_CMD_SEAL: seal data to current PCR state.
 *   Host writes data in DATA area (after 4-byte token).
 *   Crypto core stores data in slot 6 and PCR policy in slot 7.
 *
 * SHARED_CMD_UNSEAL: unseal data if PCRs match the policy.
 *   Crypto core checks current PCRs against stored policy.
 *   If they match, data is returned in DATA area (after token).
 *   If not, SHARED_STATUS_PCR_MISMATCH is returned.
 *
 * SEAL_DATA_SLOT: Secure Storage slot for sealed data.
 * SEAL_POLICY_SLOT: Secure Storage slot for the PCR policy hash.
 * ------------------------------------------------------------------------- */
#define SHARED_CMD_SEAL           0x07  /* seal data to current PCR state */
#define SHARED_CMD_UNSEAL         0x08  /* unseal data if PCRs match */

#define SEAL_DATA_SLOT            6     /* slot for sealed data */
#define SEAL_POLICY_SLOT          7     /* slot for PCR policy hash */

#define SHARED_STATUS_PCR_MISMATCH 0x0B  /* PCRs changed, cannot unseal */
#define SHARED_STATUS_NOT_SEALED   0x0C  /* nothing sealed yet */

/* -------------------------------------------------------------------------
 * Measured Launch with ELF validation
 *
 * The host sends an ELF header to the crypto core for validation.
 * The core checks magic number, architecture (RISC-V), and class
 * (64-bit). Then the host sends each section for measurement.
 * The core compares the measurement against a whitelist.
 *
 * SHARED_CMD_ELF_VALIDATE: validate an ELF header (64 bytes).
 *   Host writes ELF header in DATA after 4-byte token.
 *   Core checks magic, class, arch. Returns OK or error.
 *
 * SHARED_CMD_ELF_CHECK_HASH: check a section hash against whitelist.
 *   Host writes the section data for measurement.
 *   Core hashes it and checks against registered golden hashes.
 *   Returns OK if it matches a known-good hash, or REJECTED.
 *
 * SHARED_CMD_ELF_REGISTER: register a golden hash for a section.
 *   Used during provisioning to set up the whitelist.
 *   Host sends the hash to add to the whitelist.
 * ------------------------------------------------------------------------- */
#define SHARED_CMD_ELF_VALIDATE    0x09  /* validate ELF header */
#define SHARED_CMD_ELF_CHECK_HASH  0x0A  /* check section against whitelist */
#define SHARED_CMD_ELF_REGISTER    0x0B  /* register a golden hash */

#define SHARED_STATUS_BAD_ELF      0x0D  /* invalid ELF header */
#define SHARED_STATUS_ELF_OK       0x0E  /* valid RISC-V ELF */
#define SHARED_STATUS_HASH_MATCH   0x0F  /* section matches whitelist */
#define SHARED_STATUS_HASH_REJECT  0x10  /* section not in whitelist */
#define SHARED_STATUS_WL_FULL      0x11  /* whitelist is full */
#define SHARED_STATUS_WL_REGISTERED 0x12 /* hash registered in whitelist */

#define ELF_WHITELIST_MAX          4     /* max entries in the whitelist */

/* -------------------------------------------------------------------------
 * Supply Chain Attestation
 *
 * Each component in the firmware supply chain (bootloader, kernel,
 * application) is "signed" by its vendor using HMAC-SHA256 with
 * a vendor-specific key. The RoT stores the vendor keys and
 * verifies the signature of each component before allowing it.
 *
 * This follows the model described in NIST SP 800-193 (Platform
 * Firmware Resiliency Guidelines). Every piece of firmware must
 * be traceable to an authorized supplier.
 *
 * SHARED_CMD_CHAIN_ADD_VENDOR: register a vendor key (16 bytes).
 *   Host sends vendor ID (1 byte) + vendor key (16 bytes).
 *
 * SHARED_CMD_CHAIN_VERIFY: verify a signed component.
 *   Host sends vendor ID (1 byte) + signature (32 bytes) + payload.
 *   Core computes HMAC-SHA256(vendor_key, payload) and compares
 *   with the provided signature.
 * ------------------------------------------------------------------------- */
#define SHARED_CMD_CHAIN_ADD_VENDOR  0x0C  /* register a vendor key */
#define SHARED_CMD_CHAIN_VERIFY      0x0D  /* verify a signed component */

/*
 * Runtime attestation (OE3).
 *
 * ATTEST_BEGIN opens a measurement window and carries a nonce supplied
 * by the external verifier. ATTEST_END closes it and returns the
 * counter deltas accumulated in between, together with the nonce and
 * the PCR state, signed by the crypto core.
 *
 * The nonce is what makes the response fresh. A replayed report from a
 * healthy moment carries the wrong nonce and is rejected. And if the
 * device does not answer within the verifier's timeout, it is treated
 * as compromised, which covers the client that simply never calls.
 *
 * The crypto core does not decide whether the system is healthy. It
 * guarantees that the metrics are trustworthy: collected where they
 * cannot be forged, bounded by a defined window, and delivered signed.
 * The verdict belongs to the external verifier.
 */
#define SHARED_CMD_ATTEST_BEGIN   0x0E  /* open a window, carries a nonce */
#define SHARED_CMD_ATTEST_END     0x0F  /* close it and return the report */
#define SHARED_CMD_ATTEST_COST    0x10  /* report the cost of the attestation path */

/* Nonce size, in bytes, carried in the DATA area of ATTEST_BEGIN */
#define ATTEST_NONCE_SIZE  16

#define CHAIN_MAX_VENDORS            4     /* max vendor keys */

#define SHARED_STATUS_VENDOR_OK      0x13  /* vendor key registered */
#define SHARED_STATUS_CHAIN_OK       0x14  /* component signature valid */
#define SHARED_STATUS_CHAIN_FAIL     0x15  /* signature mismatch */
#define SHARED_STATUS_UNKNOWN_VENDOR 0x16  /* vendor ID not registered */
#define SHARED_STATUS_VENDORS_FULL   0x17  /* vendor table is full */

/* status codes that M-mode writes back */
#define SHARED_STATUS_OK     0x00
#define SHARED_STATUS_ERROR  0x01
#define SHARED_STATUS_BUSY   0x02

void pmp_setup(void);

#endif /* PMP_H */
