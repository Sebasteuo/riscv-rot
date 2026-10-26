/* ==========================================================================
 * pcr.c - Platform Configuration Registers implementation
 * ==========================================================================
 *
 * Each PCR is a 32-byte SHA-256 digest that starts at all zeros.
 * The only way to change a PCR is with the extend operation:
 *
 *   PCR_new = SHA-256(PCR_old || measurement)
 *
 * This means each PCR accumulates a chain of measurements. If you
 * know what the PCR should be (because you know what software should
 * be running), you can verify the system has not been tampered with.
 *
 * The extend operation is one-way, so you cannot "un-extend" a PCR
 * to remove a measurement. The only way to reset a PCR is to
 * reboot the system (pcr_init sets them all to zero).
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#include "pcr.h"
#include "uart.h"
#include "secret.h"

/* the PCR bank: 3 registers of 32 bytes each */
static uint8_t pcr_bank[PCR_COUNT][SHA256_DIGEST_SIZE] __secret;

/* Fixed marker extended into the runtime PCR on a deviation verdict. */
const uint8_t pcr_deviation_mark[SHA256_DIGEST_SIZE] = "RISCV-ROT-DEVIATION-MARK-v1";

/* -------------------------------------------------------------------------
 * pcr_init - reset all PCRs to zero
 *
 * Called once at boot. All PCRs start at 0x000...000 (32 zero bytes).
 * This is the known initial state before any measurements.
 * ------------------------------------------------------------------------- */
void pcr_init(void)
{
    int i, j;

    for (i = 0; i < PCR_COUNT; i++) {
        for (j = 0; j < SHA256_DIGEST_SIZE; j++) {
            pcr_bank[i][j] = 0;
        }
    }

    uart_puts("[PCR] Initialized ");
    uart_put_hex(PCR_COUNT);
    uart_puts(" PCR registers (all zeros)\n");
}

/* -------------------------------------------------------------------------
 * pcr_extend - extend a PCR with a measurement hash
 *
 * The new PCR value is: SHA-256(old_PCR || data_hash)
 * We concatenate the current 32-byte PCR with the 32-byte measurement
 * into a 64-byte buffer, hash it, and that becomes the new PCR value.
 *
 * This is exactly how a real TPM does it (TPM spec Part 1, PCR Extend).
 * ------------------------------------------------------------------------- */
int pcr_extend(int idx, const uint8_t data_hash[SHA256_DIGEST_SIZE])
{
    uint8_t concat[SHA256_DIGEST_SIZE * 2]; /* 64 bytes: old PCR + new hash */
    int i;

    if (idx < 0 || idx >= PCR_COUNT) {
        uart_puts("[PCR] ERROR: invalid PCR index\n");
        return -1;
    }

    /* build the concatenation: PCR_old || data_hash */
    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        concat[i] = pcr_bank[idx][i];
    }
    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        concat[SHA256_DIGEST_SIZE + i] = data_hash[i];
    }

    /* hash the concatenation and store as the new PCR value */
    sha256(concat, SHA256_DIGEST_SIZE * 2, pcr_bank[idx]);

    return 0;
}

/* -------------------------------------------------------------------------
 * pcr_read - copy the current PCR value to output buffer
 * ------------------------------------------------------------------------- */
int pcr_read(int idx, uint8_t output[SHA256_DIGEST_SIZE])
{
    int i;

    if (idx < 0 || idx >= PCR_COUNT) {
        return -1;
    }

    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        output[i] = pcr_bank[idx][i];
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * pcr_measure_and_extend - hash a block of memory then extend a PCR
 *
 * This is the typical operation: you point it at a chunk of firmware
 * code or data, it computes the SHA-256 hash, and extends the result
 * into the specified PCR.
 *
 * For example, to measure the PMP module:
 *   pcr_measure_and_extend(0, &pmp_setup, size_of_pmp_code);
 *
 * The PCR then reflects the exact contents of that code.
 * If someone changes even one byte, the PCR value is different.
 * ------------------------------------------------------------------------- */
int pcr_measure_and_extend(int idx, const uint8_t *data, uint32_t len)
{
    uint8_t hash[SHA256_DIGEST_SIZE];

    if (idx < 0 || idx >= PCR_COUNT) {
        uart_puts("[PCR] ERROR: invalid PCR index\n");
        return -1;
    }

    /* first hash the data */
    sha256(data, len, hash);

    uart_puts("[PCR] Measured ");
    uart_put_hex(len);
    uart_puts(" bytes, hash = ");
    uart_put_hex(hash[0]);
    uart_put_hex(hash[1]);
    uart_put_hex(hash[2]);
    uart_put_hex(hash[3]);
    uart_puts("...\n");

    /* then extend the PCR with the hash */
    return pcr_extend(idx, hash);
}

/* -------------------------------------------------------------------------
 * pcr_dump - print all PCR values
 * ------------------------------------------------------------------------- */
void pcr_dump(void)
{
    int i, j;

    uart_puts("[PCR] === PCR dump ===\n");
    for (i = 0; i < PCR_COUNT; i++) {
        uart_puts("[PCR]  PCR");
        uart_put_hex(i);
        uart_puts(": ");
        /* print first 8 bytes of the digest */
        for (j = 0; j < 8; j++) {
            uart_put_hex(pcr_bank[i][j]);
        }
        uart_puts("...\n");
    }
    uart_puts("[PCR] === End dump ===\n");
}
