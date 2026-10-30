/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */
/* ==========================================================================
 * sha256.h - SHA-256 hash function for bare-metal
 * ==========================================================================
 *
 * Standalone SHA-256 implementation. No dependencies on any library.
 * Based on the FIPS 180-4 specification from NIST.
 *
 * We need this for:
 *   - PCR extend operations (hash chaining)
 *   - Key derivation from seeds (HKDF uses SHA-256 internally)
 *   - Measuring firmware integrity (hashing code sections)
 *
 * Usage:
 *   sha256_ctx ctx;
 *   sha256_init(&ctx);
 *   sha256_update(&ctx, data, length);
 *   sha256_final(&ctx, output);  // output is 32 bytes
 *
 * Or the shortcut:
 *   sha256(data, length, output);
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

#define SHA256_DIGEST_SIZE  32  /* 256 bits = 32 bytes */
#define SHA256_BLOCK_SIZE   64  /* 512 bits = 64 bytes */

typedef struct {
    uint32_t state[8];          /* hash state (A-H) */
    uint64_t count;             /* number of bytes processed */
    uint8_t  buf[SHA256_BLOCK_SIZE]; /* partial block buffer */
} sha256_ctx;

/* step by step API */
void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *data, uint32_t len);
void sha256_final(sha256_ctx *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);

/* one-shot convenience function */
void sha256(const uint8_t *data, uint32_t len, uint8_t digest[SHA256_DIGEST_SIZE]);

#endif /* SHA256_H */
