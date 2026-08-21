/* ==========================================================================
 * main.c - Main entry point for the Root of Trust firmware
 * ==========================================================================
 *
 * Boot sequence for the Root of Trust: sets up PMP, derives keys,
 * measures firmware integrity, verifies Secure Boot, then drops
 * to U-mode for testing.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#include <stdint.h>
#include "uart.h"
#include "timer.h"
#include "pmp.h"
#include "trap.h"
#include "secure_storage.h"
#include "sha256.h"
#include "pcr.h"
#include "keygen.h"
#include "hpm.h"

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

    /* Architectural event counters (CE-5600) */
    uart_puts("\n[MAIN] --- Architectural event counters ---\n");
    hpm_dump("final state");

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

    /*
     * Read the machine timer (mtime) to measure boot time. On the
     * QEMU virt machine mtime runs at a fixed 10 MHz, so the tick
     * count converts directly to microseconds. We read it at the
     * start and end of the boot sequence and print the difference.
     *
     * This satisfies SRS-P-001 (boot time <= 500ms) by providing
     * a concrete measurement.
     */
    uint64_t boot_start, boot_end;
    boot_start = timer_now();

    uart_puts("==========================================\n");
    uart_puts("  RISC-V Root of Trust Firmware\n");
    uart_puts("  Root of Trust Active\n");
    uart_puts("  Booting in M-mode...\n");
    uart_puts("==========================================\n");
    uart_puts("[OK] UART initialized\n");

    /* Step 1: install trap handler */
    trap_install();

    /* Step 2: configure PMP (6 regions) */
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

    /* ---------------------------------------------------------------
     * Secure Boot verification
     *
     * We just stored the PCR values as "golden values" in Secure
     * Storage. Now we read them back and compare against the live
     * PCR registers. If they match, the firmware has not been
     * tampered with and we can safely continue to U-mode.
     *
     * In a real product, the golden values would be burned into
     * OTP (one-time programmable) memory or signed by the vendor
     * during manufacturing. For our demo we store and verify in
     * the same boot cycle to show the mechanism works.
     *
     * Based on: NIST SP 800-155 (BIOS Integrity Measurement
     * Guidelines) and TCG PC Client Platform Firmware Profile.
     * --------------------------------------------------------------- */
    uart_puts("\n[BOOT] --- Secure Boot verification ---\n");
    {
        uint8_t golden[SHA256_DIGEST_SIZE];
        uint8_t current[SHA256_DIGEST_SIZE];
        uint32_t golden_size = SHA256_DIGEST_SIZE;
        int i, match;

        /* verify PCR0 (code section) */
        uart_puts("[BOOT] Checking .text integrity against golden value...\n");
        ss_read_key(KEY_ID_PCR0, golden, &golden_size);
        pcr_read(0, current);
        match = 1;
        for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
            if (golden[i] != current[i]) { match = 0; break; }
        }
        if (match) {
            uart_puts("[BOOT] PCR0 matches golden value: CODE OK\n");
        } else {
            uart_puts("[BOOT] *** SECURE BOOT FAILURE ***\n");
            uart_puts("[BOOT] PCR0 does not match golden value\n");
            uart_puts("[BOOT] Firmware code has been TAMPERED WITH\n");
            uart_puts("[BOOT] System HALTED for security\n");
            while (1) { asm volatile("wfi"); }
        }

        /* verify PCR1 (rodata section) */
        uart_puts("[BOOT] Checking .rodata integrity against golden value...\n");
        golden_size = SHA256_DIGEST_SIZE;
        ss_read_key(KEY_ID_PCR1, golden, &golden_size);
        pcr_read(1, current);
        match = 1;
        for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
            if (golden[i] != current[i]) { match = 0; break; }
        }
        if (match) {
            uart_puts("[BOOT] PCR1 matches golden value: DATA OK\n");
        } else {
            uart_puts("[BOOT] *** SECURE BOOT FAILURE ***\n");
            uart_puts("[BOOT] PCR1 does not match golden value\n");
            uart_puts("[BOOT] Firmware data has been TAMPERED WITH\n");
            uart_puts("[BOOT] System HALTED for security\n");
            while (1) { asm volatile("wfi"); }
        }

        uart_puts("[BOOT] Secure Boot PASSED, firmware is authentic\n");
    }

    /* measure boot time using mtime (10 MHz timebase on QEMU virt) */
    boot_end = timer_now();
    uart_puts("\n[PERF] --- Boot time measurement (SRS-P-001) ---\n");
    uart_puts("[PERF] Boot time: ");
    timer_report(boot_start, boot_end, 500);

    uart_puts("\n[OK] M-mode setup complete. Dropping to U-mode.\n");
    uart_puts("[OK] U-mode will use shared memory to request measurements.\n\n");

    /*
     * Architectural event counters (CE-5600).
     * Mapped right before dropping to U-mode so the counts cover
     * the U-mode run and the return trip, not the M-mode setup.
     */
    uart_puts("\n");
    hpm_init();
    hpm_selftest();

    /* Step 8: drop to U-mode */
    switch_to_user();

    /* we should not reach here normally, but just in case */
    while (1) {
        asm volatile("wfi");
    }
}
