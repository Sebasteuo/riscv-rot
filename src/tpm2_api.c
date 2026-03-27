/* ==========================================================================
 * tpm2_api.c - TPM 2.0 compatible API implementation
 * ==========================================================================
 *
 * This file implements the TPM2 API defined in tpm2_api.h.
 * Each function translates a clean API call into the low-level
 * shared memory protocol that our crypto core understands.
 *
 * The shared memory zone at SHARED_BASE has this layout:
 *   offset 0x00: CMD    (which command to execute)
 *   offset 0x04: SIZE   (how many bytes of data)
 *   offset 0x08: PCR_IDX (which PCR, for measure commands)
 *   offset 0x0C: STATUS (result code from the crypto core)
 *   offset 0x10: DATA   (payload, up to ~4KB)
 *
 * The session token (4 bytes) is always written at the start of
 * DATA for commands that require a session.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#include "tpm2_api.h"
#include "pmp.h"

/* -------------------------------------------------------------------------
 * Internal state: pointers to shared memory and session token
 * ------------------------------------------------------------------------- */
static volatile uint32_t *tpm2_shared = (volatile uint32_t *)SHARED_BASE;
static volatile uint8_t  *tpm2_data   = (volatile uint8_t *)(SHARED_BASE + SHARED_OFF_DATA);
static uint8_t tpm2_token[4] = {0, 0, 0, 0};
static uint8_t tpm2_initialized = 0;

/* -------------------------------------------------------------------------
 * do_ecall - trigger a trap to M-mode and return the status
 * ------------------------------------------------------------------------- */
static uint32_t tpm2_ecall(void)
{
    asm volatile("ecall");
    return tpm2_shared[SHARED_OFF_STATUS / 4];
}

/* -------------------------------------------------------------------------
 * write_token - write the session token to the first 4 bytes of DATA
 * ------------------------------------------------------------------------- */
static void write_token(void)
{
    tpm2_data[0] = tpm2_token[0];
    tpm2_data[1] = tpm2_token[1];
    tpm2_data[2] = tpm2_token[2];
    tpm2_data[3] = tpm2_token[3];
}

/* -------------------------------------------------------------------------
 * translate_status - convert crypto core status to TPM2_RC codes
 *
 * The crypto core uses its own status codes (0x00-0x17). This
 * function maps them to the TPM 2.0 return code convention.
 * ------------------------------------------------------------------------- */
static TPM2_RC translate_status(uint32_t raw)
{
    switch (raw) {
    case SHARED_STATUS_OK:           return TPM2_RC_SUCCESS;
    case SHARED_STATUS_ERROR:        return TPM2_RC_FAILURE;
    case SHARED_STATUS_LOCKED:       return TPM2_RC_LOCKOUT;
    case SHARED_STATUS_AUTH_FAIL:    return TPM2_RC_AUTHFAIL;
    case SHARED_STATUS_AUTH_OK:      return TPM2_RC_SUCCESS;
    case SHARED_STATUS_NO_AUTH:      return TPM2_RC_NO_AUTH;
    case SHARED_STATUS_SESSION_OK:   return TPM2_RC_SUCCESS;
    case SHARED_STATUS_SESSION_EXPIRED: return TPM2_RC_EXPIRED;
    case SHARED_STATUS_BAD_TOKEN:    return TPM2_RC_BAD_TOKEN;
    case SHARED_STATUS_ROLLBACK:     return TPM2_RC_ROLLBACK;
    case SHARED_STATUS_PCR_MISMATCH: return TPM2_RC_PCR_MISMATCH;
    case SHARED_STATUS_NOT_SEALED:   return TPM2_RC_NOT_SEALED;
    case SHARED_STATUS_BAD_ELF:      return TPM2_RC_BAD_ELF;
    case SHARED_STATUS_ELF_OK:       return TPM2_RC_SUCCESS;
    case SHARED_STATUS_HASH_MATCH:   return TPM2_RC_SUCCESS;
    case SHARED_STATUS_HASH_REJECT:  return TPM2_RC_HASH_REJECT;
    case SHARED_STATUS_WL_REGISTERED: return TPM2_RC_SUCCESS;
    case SHARED_STATUS_VENDOR_OK:    return TPM2_RC_SUCCESS;
    case SHARED_STATUS_CHAIN_OK:     return TPM2_RC_SUCCESS;
    case SHARED_STATUS_CHAIN_FAIL:   return TPM2_RC_CHAIN_FAIL;
    case SHARED_STATUS_UNKNOWN_VENDOR: return TPM2_RC_UNKNOWN_VENDOR;
    default:                         return TPM2_RC_FAILURE;
    }
}

/* =========================================================================
 * Public API implementation
 * ========================================================================= */

TPM2_RC TPM2_Startup(const uint8_t *password, uint32_t pass_len)
{
    uint32_t i, raw;

    /* step 1: authenticate */
    for (i = 0; i < pass_len && i < AUTH_PASSWORD_MAX_LEN; i++) {
        tpm2_data[i] = password[i];
    }
    tpm2_shared[SHARED_OFF_CMD / 4] = SHARED_CMD_AUTH;
    tpm2_shared[SHARED_OFF_SIZE / 4] = pass_len;
    raw = tpm2_ecall();

    if (raw != SHARED_STATUS_AUTH_OK) {
        return translate_status(raw);
    }

    /* step 2: start session */
    tpm2_shared[SHARED_OFF_CMD / 4] = SHARED_CMD_START_SESSION;
    tpm2_shared[SHARED_OFF_SIZE / 4] = 0;
    raw = tpm2_ecall();

    if (raw == SHARED_STATUS_SESSION_OK) {
        tpm2_token[0] = tpm2_data[0];
        tpm2_token[1] = tpm2_data[1];
        tpm2_token[2] = tpm2_data[2];
        tpm2_token[3] = tpm2_data[3];
        tpm2_initialized = 1;
        return TPM2_RC_SUCCESS;
    }

    return translate_status(raw);
}

TPM2_RC TPM2_Shutdown(void)
{
    tpm2_shared[SHARED_OFF_CMD / 4] = SHARED_CMD_NONE;
    tpm2_initialized = 0;
    asm volatile("ecall");
    return TPM2_RC_SUCCESS;
}

TPM2_RC TPM2_PCR_Extend(uint32_t pcr_idx, const uint8_t *data, uint32_t data_len)
{
    uint32_t i;

    if (!tpm2_initialized) return TPM2_RC_NO_AUTH;
    if (data_len > 4000) return TPM2_RC_FAILURE;

    write_token();
    for (i = 0; i < data_len; i++) {
        tpm2_data[4 + i] = data[i];
    }

    tpm2_shared[SHARED_OFF_CMD / 4] = SHARED_CMD_MEASURE;
    tpm2_shared[SHARED_OFF_SIZE / 4] = 4 + data_len;
    tpm2_shared[SHARED_OFF_PCR_IDX / 4] = pcr_idx;

    return translate_status(tpm2_ecall());
}

TPM2_RC TPM2_Quote(uint8_t signature[32])
{
    uint32_t i, raw;

    if (!tpm2_initialized) return TPM2_RC_NO_AUTH;

    write_token();
    tpm2_shared[SHARED_OFF_CMD / 4] = SHARED_CMD_QUOTE;
    tpm2_shared[SHARED_OFF_SIZE / 4] = 4;

    raw = tpm2_ecall();

    if (raw == SHARED_STATUS_OK && signature) {
        /* signature is at DATA offset 100 (after 3 PCRs of 32 bytes each) */
        for (i = 0; i < 32; i++) {
            signature[i] = tpm2_data[4 + 96 + i];
        }
    }

    return translate_status(raw);
}

TPM2_RC TPM2_Seal(const uint8_t *data, uint32_t data_len)
{
    uint32_t i;

    if (!tpm2_initialized) return TPM2_RC_NO_AUTH;
    if (data_len > 32) return TPM2_RC_FAILURE;

    write_token();
    for (i = 0; i < data_len; i++) {
        tpm2_data[4 + i] = data[i];
    }

    tpm2_shared[SHARED_OFF_CMD / 4] = SHARED_CMD_SEAL;
    tpm2_shared[SHARED_OFF_SIZE / 4] = 4 + data_len;

    return translate_status(tpm2_ecall());
}

TPM2_RC TPM2_Unseal(uint8_t *out, uint32_t max_len)
{
    uint32_t i, raw;

    if (!tpm2_initialized) return TPM2_RC_NO_AUTH;

    write_token();
    tpm2_shared[SHARED_OFF_CMD / 4] = SHARED_CMD_UNSEAL;
    tpm2_shared[SHARED_OFF_SIZE / 4] = 4;

    raw = tpm2_ecall();

    if (raw == SHARED_STATUS_OK && out) {
        for (i = 0; i < max_len; i++) {
            out[i] = tpm2_data[4 + i];
        }
    }

    return translate_status(raw);
}

TPM2_RC TPM2_NV_Read(uint32_t *counter)
{
    uint32_t raw;

    if (!tpm2_initialized) return TPM2_RC_NO_AUTH;

    write_token();
    tpm2_shared[SHARED_OFF_CMD / 4] = SHARED_CMD_NV_READ;
    tpm2_shared[SHARED_OFF_SIZE / 4] = 4;

    raw = tpm2_ecall();

    if (raw == SHARED_STATUS_OK && counter) {
        *counter = ((uint32_t)tpm2_data[4] << 24)
                 | ((uint32_t)tpm2_data[5] << 16)
                 | ((uint32_t)tpm2_data[6] <<  8)
                 | ((uint32_t)tpm2_data[7]);
    }

    return translate_status(raw);
}

TPM2_RC TPM2_NV_Increment(uint32_t expected_version, uint32_t *new_value)
{
    uint32_t raw;

    if (!tpm2_initialized) return TPM2_RC_NO_AUTH;

    write_token();
    tpm2_data[4] = (expected_version >> 24) & 0xFF;
    tpm2_data[5] = (expected_version >> 16) & 0xFF;
    tpm2_data[6] = (expected_version >>  8) & 0xFF;
    tpm2_data[7] = (expected_version >>  0) & 0xFF;

    tpm2_shared[SHARED_OFF_CMD / 4] = SHARED_CMD_NV_INCREMENT;
    tpm2_shared[SHARED_OFF_SIZE / 4] = 8;

    raw = tpm2_ecall();

    if (raw == SHARED_STATUS_OK && new_value) {
        *new_value = ((uint32_t)tpm2_data[4] << 24)
                   | ((uint32_t)tpm2_data[5] << 16)
                   | ((uint32_t)tpm2_data[6] <<  8)
                   | ((uint32_t)tpm2_data[7]);
    }

    return translate_status(raw);
}

TPM2_RC TPM2_DictionaryAttackLockReset(void)
{
    uint32_t i, raw;

    for (i = 0; i < DA_LOCKOUT_CYCLES + 10; i++) {
        tpm2_shared[SHARED_OFF_CMD / 4] = SHARED_CMD_MEASURE;
        tpm2_shared[SHARED_OFF_SIZE / 4] = 0;
        tpm2_shared[SHARED_OFF_PCR_IDX / 4] = 0;
        asm volatile("ecall");
    }

    return TPM2_RC_SUCCESS;
}

TPM2_RC TPM2_ELF_Validate(const uint8_t elf_header[64])
{
    uint32_t i;

    if (!tpm2_initialized) return TPM2_RC_NO_AUTH;

    write_token();
    for (i = 0; i < 64; i++) {
        tpm2_data[4 + i] = elf_header[i];
    }

    tpm2_shared[SHARED_OFF_CMD / 4] = SHARED_CMD_ELF_VALIDATE;
    tpm2_shared[SHARED_OFF_SIZE / 4] = 68;

    return translate_status(tpm2_ecall());
}

TPM2_RC TPM2_ELF_RegisterHash(const uint8_t hash[32])
{
    uint32_t i;

    if (!tpm2_initialized) return TPM2_RC_NO_AUTH;

    write_token();
    for (i = 0; i < 32; i++) {
        tpm2_data[4 + i] = hash[i];
    }

    tpm2_shared[SHARED_OFF_CMD / 4] = SHARED_CMD_ELF_REGISTER;
    tpm2_shared[SHARED_OFF_SIZE / 4] = 36;

    return translate_status(tpm2_ecall());
}

TPM2_RC TPM2_ELF_CheckHash(const uint8_t *data, uint32_t data_len)
{
    uint32_t i;

    if (!tpm2_initialized) return TPM2_RC_NO_AUTH;
    if (data_len > 4000) return TPM2_RC_FAILURE;

    write_token();
    for (i = 0; i < data_len; i++) {
        tpm2_data[4 + i] = data[i];
    }

    tpm2_shared[SHARED_OFF_CMD / 4] = SHARED_CMD_ELF_CHECK_HASH;
    tpm2_shared[SHARED_OFF_SIZE / 4] = 4 + data_len;

    return translate_status(tpm2_ecall());
}

TPM2_RC TPM2_VerifySignature(uint8_t vendor_id,
                              const uint8_t signature[32],
                              const uint8_t *data, uint32_t data_len)
{
    uint32_t i;

    if (!tpm2_initialized) return TPM2_RC_NO_AUTH;
    if (data_len > 3900) return TPM2_RC_FAILURE;

    write_token();
    tpm2_data[4] = vendor_id;
    for (i = 0; i < 32; i++) {
        tpm2_data[5 + i] = signature[i];
    }
    for (i = 0; i < data_len; i++) {
        tpm2_data[37 + i] = data[i];
    }

    tpm2_shared[SHARED_OFF_CMD / 4] = SHARED_CMD_CHAIN_VERIFY;
    tpm2_shared[SHARED_OFF_SIZE / 4] = 37 + data_len;

    return translate_status(tpm2_ecall());
}

TPM2_RC TPM2_RegisterVendor(uint8_t vendor_id, const uint8_t key[16])
{
    uint32_t i;

    if (!tpm2_initialized) return TPM2_RC_NO_AUTH;

    write_token();
    tpm2_data[4] = vendor_id;
    for (i = 0; i < 16; i++) {
        tpm2_data[5 + i] = key[i];
    }

    tpm2_shared[SHARED_OFF_CMD / 4] = SHARED_CMD_CHAIN_ADD_VENDOR;
    tpm2_shared[SHARED_OFF_SIZE / 4] = 21;

    return translate_status(tpm2_ecall());
}
