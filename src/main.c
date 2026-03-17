/* ==========================================================================
 * main.c - Main entry point for the Root of Trust firmware
 * ==========================================================================
 *
 * Phase 3: now using the Secure Storage MMIO device in QEMU instead
 * of writing secrets directly to RAM. The ss_write_key/ss_read_key
 * functions talk to the device at 0x10200000 through registers.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#include <stdint.h>
#include "uart.h"
#include "pmp.h"
#include "trap.h"
#include "secure_storage.h"

extern void switch_to_user(void);

void main(void)
{
    uint8_t test_key[32] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11
    };

    uint8_t srk_data[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
    };

    uint8_t read_buf[64];
    uint32_t read_size = 0;
    int i;

    uart_puts("=================================\n");
    uart_puts("  RISC-V Root of Trust Firmware\n");
    uart_puts("  Booting in M-mode...\n");
    uart_puts("=================================\n");
    uart_puts("[OK] UART initialized\n");

    /* trap handler first so we catch any faults */
    trap_install();

    /* lock down secret RAM and Secure Storage device with PMP */
    pmp_setup();

    /* initialize the Secure Storage MMIO device */
    ss_init();

    /* --- test the Secure Storage device --- */
    uart_puts("\n[MAIN] --- Secure Storage MMIO test ---\n");

    /* write a 256-bit test key to the EK slot */
    uart_puts("[MAIN] Writing 256-bit test key to EK slot...\n");
    ss_write_key(KEY_ID_EK, test_key, 32);

    /* read it back to verify the round trip works */
    uart_puts("[MAIN] Reading back from EK slot...\n");
    if (ss_read_key(KEY_ID_EK, read_buf, &read_size) == 0) {
        uart_puts("[MAIN] Got ");
        uart_put_hex(read_size);
        uart_puts(" bytes: ");
        for (i = 0; i < (int)read_size && i < 8; i++) {
            uart_put_hex(read_buf[i]);
            uart_puts(" ");
        }
        uart_puts("...\n");

        /* verify the data matches what we wrote */
        int match = 1;
        for (i = 0; i < (int)read_size; i++) {
            if (read_buf[i] != test_key[i]) {
                match = 0;
                break;
            }
        }
        if (match) {
            uart_puts("[MAIN] Data verification PASSED, read matches write\n");
        } else {
            uart_puts("[MAIN] Data verification FAILED!\n");
        }
    }

    /* write a second key to the SRK slot */
    uart_puts("[MAIN] Writing 128-bit test key to SRK slot...\n");
    ss_write_key(KEY_ID_SRK, srk_data, 16);

    /* dump all slots */
    ss_dump();

    uart_puts("\n[MAIN] --- Secure Storage MMIO test complete ---\n");
    uart_puts("[OK] All M-mode setup complete\n\n");

    /* drop to U-mode, PMP guards both the RAM and the MMIO device */
    switch_to_user();
}
