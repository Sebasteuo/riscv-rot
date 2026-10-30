/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */
# Stage-1 entry point.
#
# Runs at the reset address in M-mode with no runtime available. Sets
# up a stack, clears bss, and hands over to C.

    .section .text.init
    .globl _start
_start:
    # Disable interrupts. Stage-1 does not use them.
    csrw    mie, zero
    csrw    mip, zero

    # Stack grows down, well above the Stage-2 load region
    li      sp, 0x80500000

    # Clear bss
    la      t0, __bss_start
    la      t1, __bss_end
1:
    bgeu    t0, t1, 2f
    sd      zero, 0(t0)
    addi    t0, t0, 8
    j       1b
2:
    call    stage1_main

    # stage1_main only returns if verification failed
3:
    wfi
    j       3b
