/* ==========================================================================
 * tpm2_api.h - TPM 2.0 compatible API for the Root of Trust
 * ==========================================================================
 *
 * This library provides a clean, standard-compliant interface to the
 * Root of Trust crypto core. Function names follow the TPM 2.0 spec
 * (Trusted Platform Module Library, Part 3: Commands) so that anyone
 * familiar with TPM programming can use this firmware immediately.
 *
 * Instead of manually writing to shared memory offsets and triggering
 * ecalls, the user just calls functions like TPM2_PCR_Extend() and
 * the library handles all the plumbing underneath.
 *
 * Usage example:
 *
 *   TPM2_Startup("RootOfTrustFW!!", 16);
 *   TPM2_PCR_Extend(2, my_binary, binary_size);
 *
 *   uint8_t signature[32];
 *   TPM2_Quote(signature);
 *
 *   TPM2_Seal(secret_data, 16);
 *   TPM2_Unseal(recovered_data, 16);
 *
 *   TPM2_Shutdown();
 *
 * All functions return a TPM2_RC (return code) following the TPM 2.0
 * convention: TPM2_RC_SUCCESS (0) on success, or an error code.
 *
 * Based on: TCG TPM 2.0 Library Specification, Part 3 (Commands)
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#ifndef TPM2_API_H
#define TPM2_API_H

#include <stdint.h>

/* -------------------------------------------------------------------------
 * Return codes (aligned with TPM 2.0 spec naming convention)
 *
 * TPM2_RC_SUCCESS means the command completed without errors.
 * Other codes indicate specific failure modes that the caller
 * can check and handle appropriately.
 * ------------------------------------------------------------------------- */
#define TPM2_RC_SUCCESS         0x000  /* command succeeded */
#define TPM2_RC_FAILURE         0x101  /* generic failure */
#define TPM2_RC_AUTHFAIL        0x10E  /* wrong password */
#define TPM2_RC_LOCKOUT         0x921  /* too many failed attempts */
#define TPM2_RC_NO_AUTH         0x182  /* not authenticated */
#define TPM2_RC_EXPIRED         0x923  /* session token expired */
#define TPM2_RC_BAD_TOKEN       0x924  /* wrong session token */
#define TPM2_RC_ROLLBACK        0x925  /* anti-rollback check failed */
#define TPM2_RC_PCR_MISMATCH    0x926  /* PCRs changed, unseal denied */
#define TPM2_RC_NOT_SEALED      0x927  /* nothing sealed yet */
#define TPM2_RC_BAD_ELF         0x928  /* invalid ELF header */
#define TPM2_RC_HASH_REJECT     0x929  /* section not in whitelist */
#define TPM2_RC_CHAIN_FAIL      0x92A  /* supply chain signature bad */
#define TPM2_RC_UNKNOWN_VENDOR  0x92B  /* vendor not registered */

typedef uint32_t TPM2_RC;

/* -------------------------------------------------------------------------
 * TPM2_Startup - initialize a session with the crypto core
 *
 * This is the first call the host must make. It authenticates with
 * the password and creates a session token. All subsequent commands
 * use this session automatically.
 *
 * password: the authentication password (max 32 bytes)
 * pass_len: length of the password in bytes
 *
 * Returns TPM2_RC_SUCCESS if authenticated and session created.
 * Returns TPM2_RC_AUTHFAIL if password is wrong.
 * Returns TPM2_RC_LOCKOUT if too many failed attempts.
 * ------------------------------------------------------------------------- */
TPM2_RC TPM2_Startup(const uint8_t *password, uint32_t pass_len);

/* -------------------------------------------------------------------------
 * TPM2_Shutdown - end the current session
 *
 * Signals the crypto core that U-mode is done. After this call,
 * no more commands can be sent without calling TPM2_Startup again.
 * ------------------------------------------------------------------------- */
TPM2_RC TPM2_Shutdown(void);

/* -------------------------------------------------------------------------
 * TPM2_PCR_Extend - measure a binary and extend a PCR register
 *
 * Sends raw binary data to the crypto core, which hashes it with
 * SHA-256 and extends the result into the specified PCR.
 *
 * pcr_idx:  which PCR to extend (0, 1, or 2)
 * data:     pointer to the binary data to measure
 * data_len: length in bytes (max ~4000 due to shared memory size)
 *
 * Returns TPM2_RC_SUCCESS if measurement was recorded.
 * ------------------------------------------------------------------------- */
TPM2_RC TPM2_PCR_Extend(uint32_t pcr_idx, const uint8_t *data, uint32_t data_len);

/* -------------------------------------------------------------------------
 * TPM2_Quote - generate a signed attestation of all PCR values
 *
 * The crypto core concatenates PCR0+PCR1+PCR2 (96 bytes) and signs
 * them with HMAC-SHA256 using the Endorsement Key. A remote verifier
 * who knows the EK can recalculate this and confirm the device is
 * authentic and the firmware has not been tampered with.
 *
 * signature: output buffer for the 32-byte HMAC signature
 *
 * Returns TPM2_RC_SUCCESS if quote was generated.
 * ------------------------------------------------------------------------- */
TPM2_RC TPM2_Quote(uint8_t signature[32]);

/* -------------------------------------------------------------------------
 * TPM2_Seal - encrypt and store data bound to current PCR state
 *
 * The data is encrypted with AES-128 using a key derived from the
 * current PCR values. If the firmware is modified later, the PCRs
 * change, the key changes, and the data cannot be decrypted.
 *
 * data:     pointer to the data to seal (max 32 bytes)
 * data_len: length in bytes
 *
 * Returns TPM2_RC_SUCCESS if data was sealed.
 * ------------------------------------------------------------------------- */
TPM2_RC TPM2_Seal(const uint8_t *data, uint32_t data_len);

/* -------------------------------------------------------------------------
 * TPM2_Unseal - decrypt data if PCR state matches the seal policy
 *
 * out:     output buffer for the decrypted data
 * max_len: size of the output buffer
 *
 * Returns TPM2_RC_SUCCESS if data was unsealed.
 * Returns TPM2_RC_PCR_MISMATCH if PCRs changed since sealing.
 * Returns TPM2_RC_NOT_SEALED if nothing was sealed.
 * ------------------------------------------------------------------------- */
TPM2_RC TPM2_Unseal(uint8_t *out, uint32_t max_len);

/* -------------------------------------------------------------------------
 * TPM2_NV_Read - read the current monotonic counter value
 *
 * counter: output pointer for the counter value
 *
 * Returns TPM2_RC_SUCCESS if counter was read.
 * ------------------------------------------------------------------------- */
TPM2_RC TPM2_NV_Read(uint32_t *counter);

/* -------------------------------------------------------------------------
 * TPM2_NV_Increment - increment the monotonic counter
 *
 * expected_version: the minimum version number expected. If the
 *   stored counter is already higher, this is a rollback attempt
 *   and the call is rejected.
 * new_value: output pointer for the new counter value
 *
 * Returns TPM2_RC_SUCCESS if counter was incremented.
 * Returns TPM2_RC_ROLLBACK if expected_version < current counter.
 * ------------------------------------------------------------------------- */
TPM2_RC TPM2_NV_Increment(uint32_t expected_version, uint32_t *new_value);

/* -------------------------------------------------------------------------
 * TPM2_DictionaryAttackLockReset - wait for lockout to expire
 *
 * If the system is in lockout due to too many failed auth attempts,
 * this function sends dummy ecalls to tick down the lockout counter
 * until it expires.
 *
 * Returns TPM2_RC_SUCCESS when the lockout has expired.
 * ------------------------------------------------------------------------- */
TPM2_RC TPM2_DictionaryAttackLockReset(void);

/* -------------------------------------------------------------------------
 * TPM2_ELF_Validate - validate an ELF header
 *
 * Sends a 64-byte ELF header to the crypto core for validation.
 * Checks magic number, class (64-bit), endianness, and architecture.
 *
 * elf_header: pointer to the 64-byte ELF header
 *
 * Returns TPM2_RC_SUCCESS if the header is a valid RISC-V ELF64.
 * Returns TPM2_RC_BAD_ELF if validation fails.
 * ------------------------------------------------------------------------- */
TPM2_RC TPM2_ELF_Validate(const uint8_t elf_header[64]);

/* -------------------------------------------------------------------------
 * TPM2_ELF_RegisterHash - register a golden hash in the whitelist
 *
 * hash: 32-byte SHA-256 hash of an approved binary section
 *
 * Returns TPM2_RC_SUCCESS if registered.
 * ------------------------------------------------------------------------- */
TPM2_RC TPM2_ELF_RegisterHash(const uint8_t hash[32]);

/* -------------------------------------------------------------------------
 * TPM2_ELF_CheckHash - check a binary section against the whitelist
 *
 * data:     pointer to the binary section
 * data_len: length in bytes
 *
 * Returns TPM2_RC_SUCCESS if the section matches a whitelist entry.
 * Returns TPM2_RC_HASH_REJECT if not in whitelist.
 * ------------------------------------------------------------------------- */
TPM2_RC TPM2_ELF_CheckHash(const uint8_t *data, uint32_t data_len);

/* -------------------------------------------------------------------------
 * TPM2_VerifySignature - verify a supply chain component signature
 *
 * vendor_id: the vendor who signed this component
 * signature: 32-byte HMAC-SHA256 signature
 * data:      the component binary
 * data_len:  length in bytes
 *
 * Returns TPM2_RC_SUCCESS if signature is valid.
 * Returns TPM2_RC_CHAIN_FAIL if signature mismatch.
 * Returns TPM2_RC_UNKNOWN_VENDOR if vendor not registered.
 * ------------------------------------------------------------------------- */
TPM2_RC TPM2_VerifySignature(uint8_t vendor_id,
                              const uint8_t signature[32],
                              const uint8_t *data, uint32_t data_len);

/* -------------------------------------------------------------------------
 * TPM2_RegisterVendor - register a vendor key for supply chain
 *
 * vendor_id: unique vendor identifier (0-255)
 * key:       16-byte vendor signing key
 *
 * Returns TPM2_RC_SUCCESS if vendor was registered.
 * ------------------------------------------------------------------------- */
TPM2_RC TPM2_RegisterVendor(uint8_t vendor_id, const uint8_t key[16]);

#endif /* TPM2_API_H */
