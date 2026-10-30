/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */
/* ==========================================================================
 * pcr.h - Platform Configuration Registers
 * ==========================================================================
 *
 * PCRs record measurements of the system state. Each PCR is a SHA-256
 * digest (32 bytes). The key operation is "extend":
 *
 *   PCR_new = SHA-256(PCR_old || new_measurement)
 *
 * This chains measurements together. If any measurement changes, the
 * final PCR value is completely different. You cannot undo an extend
 * or fake a specific PCR value without knowing the entire chain.
 *
 * We use 3 PCRs for now:
 *   PCR0 - firmware code measurement
 *   PCR1 - firmware data measurement
 *   PCR2 - runtime measurements (for future use)
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#ifndef PCR_H
#define PCR_H

#include <stdint.h>
#include "sha256.h"

/*
 * PCR 0 to 2 hold boot time measurements.
 *
 * PCR 3 holds the runtime attestation result. It starts at zero and is
 * extended only when a window closes with a deviation verdict, so a secret
 * sealed against the policy means "booted correctly and no deviation seen
 * since then".
 */
#define PCR_COUNT        4
#define PCR_RUNTIME_IDX  3

/*
 * The value extended into PCR_RUNTIME_IDX when a window closes with a
 * deviation verdict. A fixed constant rather than the counter values, so a
 * verifier can work out the expected PCR after n deviations without needing
 * an event log from the device.
 */
extern const uint8_t pcr_deviation_mark[SHA256_DIGEST_SIZE];

/* initialize all PCRs to zero (called once at boot) */
void pcr_init(void);

/* extend a PCR with a new measurement:
 * PCR[idx] = SHA-256(PCR[idx] || data_hash)
 * data_hash must be 32 bytes (a SHA-256 digest) */
int pcr_extend(int idx, const uint8_t data_hash[SHA256_DIGEST_SIZE]);

/* read the current value of a PCR into output (32 bytes) */
int pcr_read(int idx, uint8_t output[SHA256_DIGEST_SIZE]);

/* measure a block of memory (hash it) and extend into a PCR */
int pcr_measure_and_extend(int idx, const uint8_t *data, uint32_t len);

/* print all PCR values for debug */
void pcr_dump(void);

#endif /* PCR_H */
