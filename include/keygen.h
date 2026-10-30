/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */
/* ==========================================================================
 * keygen.h - Key generation and derivation
 * ==========================================================================
 *
 * Generates cryptographic keys from a seed using HKDF-like derivation.
 * Following the TPM 2.0 spec (Part 1, Section 8.4.9), keys are derived
 * from a persistent seed rather than generated randomly. This means
 * the same seed always produces the same keys, giving the device a
 * stable identity across reboots.
 *
 * We implement a simplified KDF based on HMAC-SHA256:
 *   derived_key = HMAC-SHA256(seed, label || 0x00 || context || length)
 *
 * This is close to NIST SP 800-108 KDF in Counter Mode which is what
 * the TPM spec uses.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#ifndef KEYGEN_H
#define KEYGEN_H

#include <stdint.h>
#include "sha256.h"

/* size of the primary seed (256 bits) */
#define SEED_SIZE  32

/* HMAC-SHA256: produces a 32-byte MAC */
void hmac_sha256(const uint8_t *key, uint32_t key_len,
                 const uint8_t *data, uint32_t data_len,
                 uint8_t output[SHA256_DIGEST_SIZE]);

/* derive a key from a seed using a label string
 * output is always 32 bytes (256-bit key) */
void kdf_derive(const uint8_t seed[SEED_SIZE],
                const char *label,
                uint8_t output[SHA256_DIGEST_SIZE]);

/* generate the Endorsement Key from the endorsement seed */
void keygen_ek(const uint8_t seed[SEED_SIZE],
               uint8_t ek[SHA256_DIGEST_SIZE]);

/* generate the Storage Root Key from the storage seed */
void keygen_srk(const uint8_t seed[SEED_SIZE],
                uint8_t srk[SHA256_DIGEST_SIZE]);

/* initialize keys: generate EK and SRK from seeds, store them */
void keygen_init(void);

#endif /* KEYGEN_H */
