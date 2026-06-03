/* ==========================================================================
 * switch.c - M-mode to U-mode privilege switch
 * ==========================================================================
 *
 * This handles dropping from M-mode down to U-mode. It is trickier
 * than it sounds because RISC-V does not have a "go to user mode"
 * instruction. Instead we have to abuse mret.
 *
 * mret is normally used to return from a trap, it goes back to
 * whatever mode was running before. But we can trick it into jumping
 * to U-mode by setting up the CSRs as if a trap had come from U-mode:
 *
 *   1. Clear mstatus.MPP to 0
 *      MPP = Machine Previous Privilege. mret switches to whatever
 *      mode is in MPP. 0 means User, 3 means Machine. So we clear
 *      it to make mret land us in U-mode.
 *
 *   2. Put the target address in mepc
 *      mret jumps to whatever address is in mepc. We stuff the
 *      address of user_entry() in there.
 *
 *   3. Give U-mode its own stack
 *      We cannot let U-mode use the M-mode stack because then it
 *      could snoop on M-mode data. So we set up a separate one.
 *
 *   4. Fire mret
 *      The processor reads MPP, sees 0, switches to U-mode, and
 *      jumps to mepc. We are now running user_entry() with no
 *      privileges. The only way back to M-mode is through a trap.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#include <stdint.h>
#include "uart.h"
#include "pmp.h"

/* user_entry is defined in user.c */
extern void user_entry(void);

/*
 * A small 4KB stack just for U-mode.
 * Sits in regular RAM which PMP region 2 allows U-mode to access.
 * The aligned(16) is because RISC-V calling convention wants the
 * stack pointer 16-byte aligned.
 */
static uint8_t user_stack[4096] __attribute__((aligned(16), section(".umode_bss")));

/* -------------------------------------------------------------------------
 * switch_to_user - drop privileges and jump to user_entry()
 *
 * This is a one-way trip. After mret we are in U-mode and the only
 * way back is through a trap (like ecall or an access fault).
 * ------------------------------------------------------------------------- */
void switch_to_user(void)
{
    uint64_t mstatus;

    uart_puts("[SWITCH] Preparing to jump to U-mode...\n");

    /*
     * Clear MPP (bits 12-11) in mstatus to select User mode.
     * 0x1800 is a mask with bits 12 and 11 set. Inverting it and
     * ANDing clears just those two bits, everything else stays.
     * Also set MPIE (bit 7) so interrupts get enabled after mret.
     */
    asm volatile("csrr %0, mstatus" : "=r"(mstatus));
    mstatus &= ~(0x1800UL);   /* MPP = 00 = User mode */
    mstatus |= (1 << 7);      /* MPIE = 1 */
    asm volatile("csrw mstatus, %0" :: "r"(mstatus));

    uart_puts("[SWITCH] mstatus.MPP set to User mode (0)\n");

    /* tell mret where to jump */
    asm volatile("csrw mepc, %0" :: "r"((uint64_t)user_entry));

    uart_puts("[SWITCH] mepc set to user_entry at ");
    uart_put_hex((uint64_t)user_entry);
    uart_puts("\n");

    /* stack pointer for U-mode, points to the top since it grows down */
    uint64_t user_sp = (uint64_t)(user_stack + sizeof(user_stack));

    uart_puts("[SWITCH] U-mode stack at ");
    uart_put_hex(user_sp);
    uart_puts("\n");
    uart_puts("[SWITCH] Jumping to U-mode NOW!\n");
    uart_puts("=========================================\n");

    /*
     * Swap the stack and fire mret. After this we are in U-mode
     * running user_entry(). No coming back from here.
     */
    asm volatile(
        "mv sp, %0\n"
        "mret\n"
        :: "r"(user_sp)
    );
}
