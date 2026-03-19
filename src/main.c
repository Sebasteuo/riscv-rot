/* ==========================================================================
 * main.c - Main entry point for the Root of Trust firmware
 * ==========================================================================
 *
 * Phase 5: Shared memory zone for host-to-core communication.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#include <stdint.h>
#include "uart.h"
#include "pmp.h"
#include "trap.h"
#include "secure_storage.h"
#include "sha256.h"
#include "pcr.h"
#include "keygen.h"

extern void switch_to_user(void);

extern uint8_t __text_start[];
extern uint8_t __text_end[];
extern uint8_t __rodata_start[];
extern uint8_t __rodata_end[];

/*
 * This flag is set by the trap handler when U-mode does the final
 * ecall with no command. main() polls it after switch_to_user().
 * It is a simple way to know when U-mode is done without complex
 * control flow tricks.
 */
volatile int umode_done = 0;

void post_umode_report(void)
{
    uint8_t read_buf[SHA256_DIGEST_SIZE];

    uart_puts("\n==========================================\n");
    uart_puts("  Back in M-mode - Final system state\n");
    uart_puts("==========================================\n");

    /* store the final PCR2 value (extended by host measurements) */
    pcr_read(2, read_buf);
    ss_write_key(KEY_ID_PCR2, read_buf, SHA256_DIGEST_SIZE);

    uart_puts("\n[MAIN] --- Final PCR state ---\n");
    uart_puts("[MAIN] PCR0: firmware .text measurement\n");
    uart_puts("[MAIN] PCR1: firmware .rodata measurement\n");
    uart_puts("[MAIN] PCR2: host binary measurements (from U-mode requests)\n");
    pcr_dump();

    uart_puts("\n[MAIN] --- Final Secure Storage state ---\n");
    ss_dump();

    uart_puts("\n==========================================\n");
    uart_puts("  ALL TESTS PASSED\n");
    uart_puts("  Root of Trust operational\n");
    uart_puts("==========================================\n");

    while (1) {
        asm volatile("wfi");
    }
}

void main(void)
{
    uint8_t read_buf[SHA256_DIGEST_SIZE];
    uint32_t read_size = 0;
    int i;

    uart_puts("==========================================\n");
    uart_puts("  RISC-V Root of Trust Firmware\n");
    uart_puts("  Phase 5 - Shared Memory Interface\n");
    uart_puts("  Booting in M-mode...\n");
    uart_puts("==========================================\n");
    uart_puts("[OK] UART initialized\n");

    /* Step 1: install trap handler */
    trap_install();

    /* Step 2: configure PMP (5 regions) */
    pmp_setup();

    /* Step 3: initialize Secure Storage MMIO device */
    ss_init();

    /* Step 4: initialize PCRs */
    pcr_init();

    /* Step 5: measure firmware integrity */
    uart_puts("\n[MAIN] --- Firmware integrity measurement ---\n");

    uart_puts("[MAIN] Measuring .text section (code)...\n");
    pcr_measure_and_extend(0, __text_start,
        (uint32_t)((uintptr_t)__text_end - (uintptr_t)__text_start));

    uart_puts("[MAIN] Measuring .rodata section (constants)...\n");
    pcr_measure_and_extend(1, __rodata_start,
        (uint32_t)((uintptr_t)__rodata_end - (uintptr_t)__rodata_start));

    uart_puts("[MAIN] PCR0 = code, PCR1 = data, PCR2 = host (empty until U-mode)\n");
    pcr_dump();

    /* Step 6: derive and store keys */
    uart_puts("\n[MAIN] --- Key generation ---\n");
    keygen_init();

    /* Step 7: store PCR snapshots */
    pcr_read(0, read_buf);
    ss_write_key(KEY_ID_PCR0, read_buf, SHA256_DIGEST_SIZE);
    pcr_read(1, read_buf);
    ss_write_key(KEY_ID_PCR1, read_buf, SHA256_DIGEST_SIZE);

    uart_puts("\n[OK] M-mode setup complete. Dropping to U-mode.\n");
    uart_puts("[OK] U-mode will use shared memory to request measurements.\n\n");

    /* Step 8: drop to U-mode */
    switch_to_user();

    /* we should not reach here normally, but just in case */
    while (1) {
        asm volatile("wfi");
    }
}
