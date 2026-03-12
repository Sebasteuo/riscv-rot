/* ==========================================================================
 * main.c - Main entry point for the Root of Trust firmware
 * ==========================================================================
 *
 * This is where start.S jumps to after setting up the stack and
 * clearing BSS. It is the beginning of our C code.
 *
 * In Phase 1 this just printed a message to confirm the boot worked.
 * Now we are reorganizing things for Phase 2 where we will add PMP
 * configuration, the trap handler, and the jump to U-mode.
 *
 * For now main is still simple. It prints the firmware banner and
 * confirms we are running in M-mode. The PMP logic will be added
 * in the next steps.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#include <stdint.h>
#include "uart.h"

/* -------------------------------------------------------------------------
 * main - Firmware entry point
 *
 * What it does right now:
 *   1. Prints the firmware banner
 *   2. Confirms that UART works
 *   3. Sits in an infinite loop waiting
 *
 * In the next steps of Phase 2 we will:
 *   - Configure PMP regions
 *   - Install the trap handler
 *   - Jump to U-mode
 *   - Test that PMP blocks unauthorized access
 * ------------------------------------------------------------------------- */
void main(void)
{
    uart_puts("=================================\n");
    uart_puts("  RISC-V Root of Trust Firmware\n");
    uart_puts("  Booting in M-mode...\n");
    uart_puts("=================================\n");
    uart_puts("[OK] UART initialized\n");
    uart_puts("[OK] Firmware running on QEMU virt (rv64)\n");
    uart_puts("\nHello from bare-metal RISC-V!\n");

    /* infinite loop, firmware stays here waiting */
    while (1) {
        asm volatile("wfi");
    }
}
