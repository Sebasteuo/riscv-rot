/* ==========================================================================
 * trap_entry.S - Assembly trampoline for trap handling
 * ==========================================================================
 *
 * When a trap fires, the processor jumps to the address in mtvec
 * which points right here. The problem is we cannot just call a C
 * function directly because the processor does not save any registers
 * for us. If we jumped straight into C, it would clobber all the
 * registers and we would lose track of what was running before.
 *
 * So the flow is:
 *   1. Push a bunch of registers onto the stack to save them
 *   2. Call trap_handler() in C which does the actual logic
 *   3. Pop the registers back to restore everything
 *   4. mret to go back to wherever we came from
 *
 * This save-call-restore pattern is sometimes called a "trampoline"
 * because we bounce from assembly into C and back again.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

.section .text
.global trap_entry
.align 4

trap_entry:
    /*
     * Make room on the stack and save all the registers that C
     * might overwrite. 16 registers x 8 bytes = 128 bytes total.
     */
    addi sp, sp, -128

    sd ra,   0(sp)
    sd t0,   8(sp)
    sd t1,  16(sp)
    sd t2,  24(sp)
    sd t3,  32(sp)
    sd t4,  40(sp)
    sd t5,  48(sp)
    sd t6,  56(sp)
    sd a0,  64(sp)
    sd a1,  72(sp)
    sd a2,  80(sp)
    sd a3,  88(sp)
    sd a4,  96(sp)
    sd a5, 104(sp)
    sd a6, 112(sp)
    sd a7, 120(sp)

    /* now it is safe to call into C */
    call trap_handler

    /* put everything back the way it was */
    ld ra,   0(sp)
    ld t0,   8(sp)
    ld t1,  16(sp)
    ld t2,  24(sp)
    ld t3,  32(sp)
    ld t4,  40(sp)
    ld t5,  48(sp)
    ld t6,  56(sp)
    ld a0,  64(sp)
    ld a1,  72(sp)
    ld a2,  80(sp)
    ld a3,  88(sp)
    ld a4,  96(sp)
    ld a5, 104(sp)
    ld a6, 112(sp)
    ld a7, 120(sp)

    addi sp, sp, 128

    /*
     * mret returns from the trap. It restores the previous privilege
     * mode from mstatus.MPP and jumps to the address in mepc.
     *
     * Important: in our C handler we bump mepc forward by the length of
     * the trapping instruction (2 or 4 bytes) so that we skip over it.
     * Otherwise we would land right back on it and trap again forever.
     */
    mret
