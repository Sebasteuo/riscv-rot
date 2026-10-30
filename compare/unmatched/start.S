/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */
    .section .text.entry, "ax"
    .globl _start
_start:
    /* S7 monitor core has no S-mode. Only U74 application cores do. */
    csrr    t0, misa
    li      t1, 0x40000
    and     t0, t0, t1
    beqz    t0, park

    /* First U74 to claim the lock runs. The rest park. */
    la      t0, boot_lock
    li      t1, 1
    amoswap.w t1, t1, (t0)
    bnez    t1, park

    /*
     * Enable the FPU. mstatus.FS is two bits at position 13. Writing
     * 0b01 (Initial) turns floating point on. The embench objects are
     * built rv64gc/lp64d and several use doubles, so without this the
     * first FP instruction traps.
     */
    li      t0, (1 << 13)
    csrs    mstatus, t0
    fscsr   x0

    /*
     * Zero .bss. QEMU hands over cleared memory and the platform
     * relies on that. DRAM on the board comes up with whatever was
     * there. nsichneu is the benchmark that notices, since its
     * working variables are globals and its control flow depends on
     * them.
     */
    la      t0, __bss_start
    la      t1, __bss_end
1:  bgeu    t0, t1, 2f
    sd      zero, 0(t0)
    addi    t0, t0, 8
    j       1b
2:

    la      sp, stack_top
    j       fw_main

park:
    wfi
    j       park

    .section .data
    .align 3
boot_lock:
    .word 0

    .section .bss
    .align 12
stack_bottom:
    .space 16384
stack_top:
