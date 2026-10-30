/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */
    .section .text.entry, "ax"
    .globl _start
_start:
    la      sp, stack_top
    j       qmain
    .section .bss
    .align 12
    .space 8192
stack_top:
