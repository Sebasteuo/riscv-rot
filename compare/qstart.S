    .section .text.entry, "ax"
    .globl _start
_start:
    la      sp, stack_top
    j       qmain
    .section .bss
    .align 12
    .space 8192
stack_top:
