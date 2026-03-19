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

#define PCR_COUNT  3

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
