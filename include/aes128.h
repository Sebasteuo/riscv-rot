/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */
/* ==========================================================================
 * aes128.h - AES-128 block cipher
 * ==========================================================================
 *
 * Standalone AES-128 implementation for the Root of Trust firmware.
 * No external dependencies, no standard library.
 *
 * AES-128 encrypts data in blocks of 16 bytes using a 128-bit key.
 * It is the most widely used symmetric cipher in the world, found
 * in everything from HTTPS to disk encryption to TPMs.
 *
 * We use ECB mode (each block encrypted independently) which is
 * fine for our use case since we encrypt small amounts of data
 * (max 32 bytes = 2 blocks) and each sealed blob uses a unique
 * key derived from the PCR state.
 *
 * Key size:   16 bytes (128 bits)
 * Block size: 16 bytes (128 bits)
 *
 * Based on FIPS 197 (Advanced Encryption Standard).
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#ifndef AES128_H
#define AES128_H

#include <stdint.h>

#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    16
#define AES_NUM_ROUNDS  10

/* -------------------------------------------------------------------------
 * aes128_context - holds the expanded round keys
 *
 * AES takes a 16-byte key and expands it into 11 round keys
 * (one for the initial AddRoundKey, plus one per round).
 * We store all of them here so we only do the expansion once
 * and can encrypt multiple blocks with the same key.
 * ------------------------------------------------------------------------- */
typedef struct {
    uint8_t round_keys[176];  /* 11 round keys x 16 bytes = 176 bytes */
} aes128_context;

/* -------------------------------------------------------------------------
 * aes128_init - expand the key into round keys
 *
 * Call this once with your 16-byte key. After this, the context
 * is ready to encrypt or decrypt as many blocks as you want.
 * ------------------------------------------------------------------------- */
void aes128_init(aes128_context *ctx, const uint8_t key[AES_KEY_SIZE]);

/* -------------------------------------------------------------------------
 * aes128_encrypt_block - encrypt a single 16-byte block
 *
 * input:  16 bytes of plaintext
 * output: 16 bytes of ciphertext
 * The input and output buffers can be the same (in-place encryption).
 * ------------------------------------------------------------------------- */
void aes128_encrypt_block(const aes128_context *ctx,
                          const uint8_t input[AES_BLOCK_SIZE],
                          uint8_t output[AES_BLOCK_SIZE]);

/* -------------------------------------------------------------------------
 * aes128_decrypt_block - decrypt a single 16-byte block
 *
 * input:  16 bytes of ciphertext
 * output: 16 bytes of plaintext
 * The input and output buffers can be the same (in-place decryption).
 * ------------------------------------------------------------------------- */
void aes128_decrypt_block(const aes128_context *ctx,
                          const uint8_t input[AES_BLOCK_SIZE],
                          uint8_t output[AES_BLOCK_SIZE]);

/* -------------------------------------------------------------------------
 * aes128_encrypt - encrypt multiple blocks (ECB mode)
 *
 * data:     plaintext buffer (must be multiple of 16 bytes)
 * out:      ciphertext buffer (same size as data)
 * len:      length in bytes (must be multiple of 16)
 *
 * ECB mode encrypts each 16-byte block independently. This is
 * acceptable for our use case (small, unique data per seal).
 * ------------------------------------------------------------------------- */
void aes128_encrypt(const aes128_context *ctx,
                    const uint8_t *data, uint8_t *out, uint32_t len);

/* -------------------------------------------------------------------------
 * aes128_decrypt - decrypt multiple blocks (ECB mode)
 * ------------------------------------------------------------------------- */
void aes128_decrypt(const aes128_context *ctx,
                    const uint8_t *data, uint8_t *out, uint32_t len);

#endif /* AES128_H */
