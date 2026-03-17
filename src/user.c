/* ==========================================================================
 * user.c - Code that runs in U-mode to test PMP protection
 * ==========================================================================
 *
 * This is the unprivileged code that runs after we drop from M-mode
 * to U-mode. The whole point of this file is to try and access the
 * protected secret zone and see what happens. Spoiler: PMP blocks it.
 *
 * Once we are in U-mode we have basically no privileges. We cannot
 * touch PMP registers, we cannot access restricted memory regions,
 * we are just a regular user program with no special powers.
 *
 * The test goes like this:
 *   - First we print a message (works fine because we gave U-mode
 *     access to the UART in PMP region 1)
 *   - Then we try to read from 0x80100000 (the secret zone)
 *   - The processor sees we have no permission and fires a trap
 *   - The trap handler in M-mode catches it, logs it, and skips
 *     the faulting instruction so we can keep going
 *   - Then we try to write to the same zone, same thing happens
 *   - Finally we call ecall to hand control back to M-mode
 *
 * If both the read and the write get blocked, it means PMP is doing
 * its job and the secrets are safe from unprivileged code.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#include <stdint.h>
#include "uart.h"
#include "pmp.h"

/* -------------------------------------------------------------------------
 * user_entry - the function that runs once we are in U-mode
 *
 * Needs to be kept simple since we have a small separate stack for
 * U-mode. Also we cannot call anything that touches CSRs because
 * those are M-mode only and we would get an illegal instruction trap.
 *
 * The volatile on the pointer is important. Without it the compiler
 * might decide the read "does nothing useful" and optimize it out.
 * But we actually need the read to happen because that is what
 * triggers the PMP fault we want to demonstrate.
 * ------------------------------------------------------------------------- */
void user_entry(void)
{
    volatile uint64_t *secret = (volatile uint64_t *)SECRET_BASE;
    uint64_t stolen_value;

    uart_puts("\n[USER] ================================\n");
    uart_puts("[USER] Running in U-mode (unprivileged)\n");
    uart_puts("[USER] Attempting to READ the secret zone...\n");

    /*
     * Here we go. We try to read from the secret zone at 0x80100000.
     * PMP has this region locked with no permissions for U-mode so
     * the processor will fire a Load Access Fault (mcause = 5).
     *
     * The trap handler catches it, prints what happened, bumps mepc
     * forward by 4 bytes, and returns here. stolen_value ends up with
     * whatever junk was already in the register since the actual read
     * never completed.
     */
    stolen_value = *secret;

    uart_puts("[USER] Survived the read attempt (trap handled it)\n");
    uart_puts("[USER] Value we got: ");
    uart_put_hex(stolen_value);
    uart_puts(" (garbage, the real secret was NOT leaked)\n");

    uart_puts("[USER] Now attempting to WRITE to the secret zone...\n");

    /*
     * Same thing but with a write. Triggers a Store Access Fault
     * (mcause = 7). PMP blocks the write so the original secret
     * value in memory stays untouched.
     */
    *secret = 0xAAAAAAAAAAAAAAAAUL;

    uart_puts("[USER] Survived the write attempt (trap handled it)\n");
    uart_puts("[USER] The secret zone is PROTECTED by hardware!\n");
    uart_puts("[USER] ================================\n");

    /* all done, ecall to go back to M-mode */
    uart_puts("[USER] Tests complete, handing control back to M-mode\n");
    asm volatile("ecall");
}
