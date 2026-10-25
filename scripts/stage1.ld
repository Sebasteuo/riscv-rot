/*
 * Linker script for Stage-1, the minimal trusted bootloader.
 *
 * Stage-1 owns the reset address and is the only code the platform
 * trusts unconditionally. On real hardware it would live in mask ROM, and
 * under emulation it is loaded at the reset vector and never written.
 *
 * Layout:
 *   0x80000000   where Stage-2 gets loaded, must stay clear
 *   0x80400000   Stage-1 code, rodata, data and bss
 *   0x80500000   Stage-1 stack top
 *   0x84000000   Stage-2 signed image, placed there by QEMU at startup
 *
 * Stage-1 deliberately lives above the region Stage-2 occupies. A
 * loader that shares an address range with the image it loads will
 * overwrite itself mid-copy.
 */

OUTPUT_ARCH("riscv")
ENTRY(_start)

MEMORY
{
    RAM (rwx) : ORIGIN = 0x80400000, LENGTH = 1M
}

SECTIONS
{
    . = 0x80400000;

    .text : {
        KEEP(*(.text.init))
        *(.text .text.*)
    } > RAM

    .rodata : {
        __rodata_start = .;
        *(.rodata .rodata.*)
        __rodata_end = .;
    } > RAM

    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    } > RAM

    .bss : {
        __bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        __bss_end = .;
    } > RAM

    __stage1_end = .;

    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
