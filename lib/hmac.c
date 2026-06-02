/* ==========================================================================
 * hmac.c - HMAC-SHA256 (shared between M-mode and U-mode)
 * ==========================================================================
 *
 * Lives in its own file so it can sit in the shared code region: both
 * the crypto core (M-mode) and the host test code (U-mode) call it.
 * U-mode uses it to pre-compute supply chain signatures before sending
 * them to the core for verification.
 *
 * HMAC-SHA256 follows RFC 2104:
 *   HMAC(key, msg) = SHA256((key XOR opad) || SHA256((key XOR ipad) || msg))
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#include "keygen.h"

/* -------------------------------------------------------------------------
 * hmac_sha256 - HMAC using SHA-256 (RFC 2104)
 *
 * HMAC works like this:
 *   1. If the key is longer than 64 bytes, hash it first
 *   2. Pad the key to 64 bytes
 *   3. XOR the padded key with 0x36 to make the inner key (ipad)
 *   4. XOR the padded key with 0x5C to make the outer key (opad)
 *   5. inner_hash = SHA256(ipad || message)
 *   6. result = SHA256(opad || inner_hash)
 *
 * This construction ensures that the MAC depends on both the key
 * and the message in a way that is secure against forgery.
 * ------------------------------------------------------------------------- */
void hmac_sha256(const uint8_t *key, uint32_t key_len,
                 const uint8_t *data, uint32_t data_len,
                 uint8_t output[SHA256_DIGEST_SIZE])
{
    uint8_t k_pad[SHA256_BLOCK_SIZE];
    uint8_t inner_hash[SHA256_DIGEST_SIZE];
    sha256_ctx ctx;
    uint32_t i;

    /* if key is too long, hash it first */
    if (key_len > SHA256_BLOCK_SIZE) {
        sha256(key, key_len, k_pad);
        for (i = SHA256_DIGEST_SIZE; i < SHA256_BLOCK_SIZE; i++) {
            k_pad[i] = 0;
        }
    } else {
        for (i = 0; i < key_len; i++) {
            k_pad[i] = key[i];
        }
        for (i = key_len; i < SHA256_BLOCK_SIZE; i++) {
            k_pad[i] = 0;
        }
    }

    /* inner hash: SHA256((key XOR ipad) || data) */
    sha256_init(&ctx);
    for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
        k_pad[i] ^= 0x36;
    }
    sha256_update(&ctx, k_pad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner_hash);

    /* restore k_pad (undo ipad, apply opad) */
    for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
        k_pad[i] ^= 0x36 ^ 0x5C;
    }

    /* outer hash: SHA256((key XOR opad) || inner_hash) */
    sha256_init(&ctx);
    sha256_update(&ctx, k_pad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, inner_hash, SHA256_DIGEST_SIZE);
    sha256_final(&ctx, output);
}
