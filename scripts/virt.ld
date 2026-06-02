/* ==========================================================================
 * virt.ld - Linker script for the QEMU virt machine (RISC-V 64-bit)
 * ==========================================================================
 *
 * What is a linker script?
 * When we compile C or assembly code, the compiler generates object
 * files (.o) with machine code. But those files do not know WHERE in
 * memory they are supposed to live.
 *
 * The linker script tells the linker (the tool that puts everything
 * together) exactly where to place each piece of the program in memory.
 * This is critical in bare-metal because there is no operating system
 * to load the program for us.
 *
 * Why 0x80000000?
 * On the QEMU virt machine for RISC-V, RAM starts at address
 * 0x80000000. We did not pick this, it is defined by the hardware
 * (or in this case, by the QEMU virtual machine spec). When QEMU
 * boots with -bios none -kernel, it jumps straight to 0x80000000,
 * so our code has to be sitting right there.
 *
 * Phase 4 additions:
 * We now export __text_start, __text_end, __rodata_start, __rodata_end
 * so the firmware can measure (hash) its own code and data sections
 * at boot time and record the results in PCRs.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY
{
    RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 128M
}

SECTIONS
{
    . = 0x80000000;

    .text : {
        __text_start = .;
        *(.text.init)
        *(.text*)
        __text_end = .;
    } > RAM

    .rodata : {
        __rodata_start = .;
        *(.rodata*)
        __rodata_end = .;
    } > RAM

    .data : {
        *(.data*)
    } > RAM

    .got : {
        *(.got*)
    } > RAM

    .bss : {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        __bss_end = .;
    } > RAM

    .stack (NOLOAD) : {
        . = . + 0x10000;
        __stack_top = .;
    } > RAM

    .secret_data 0x80100000 : {
        . = ALIGN(8);
        __secret_data_start = .;
        *(.secret_data)
        . = ALIGN(8);
        __secret_data_end = .;
    } > RAM

    .secret (NOLOAD) : {
        . = ALIGN(8);
        __secret_start = .;
        *(.secret)
        . = ALIGN(8);
        __secret_end = .;
    } > RAM

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note*)
        *(.comment)
        *(.riscv.attributes)
        *(.interp)
        *(.dynamic)
        *(.dynsym)
        *(.dynstr)
        *(.gnu.hash)
        *(.rela*)
    }
}
