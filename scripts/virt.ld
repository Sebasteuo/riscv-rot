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
 * What sections does a program have?
 *   .text     executable code (the processor instructions)
 *   .rodata   read-only data (constants, strings)
 *   .data     initialized global variables (e.g. int x = 5)
 *   .bss      uninitialized global variables (e.g. int x;)
 *   .stack    reserved space for the stack
 *   .got      Global Offset Table, used by the compiler internally
 *             to resolve symbol addresses
 *
 * At the end we discard sections we do not need in bare-metal like
 * .dynamic, .interp, etc. Those are meant for executables that run
 * on top of an OS with a dynamic linker.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

OUTPUT_ARCH(riscv)
ENTRY(_start)

/*
 * Define the available memory.
 * ORIGIN is where RAM starts
 * LENGTH is how much RAM we have (128 MB, same as what we pass to QEMU with -m 128M)
 * rwx means this memory allows reading, writing and execution
 */
MEMORY
{
    RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 128M
}

SECTIONS
{
    /* Force everything to start at 0x80000000 */
    . = 0x80000000;

    /*
     * .text section, this is where executable code goes
     * .text.init goes first because that is where _start lives (our entry point)
     * Then the rest of the code follows (.text*)
     */
    .text : {
        *(.text.init)
        *(.text*)
    } > RAM

    /*
     * .rodata section, read-only data
     * This is where strings like "Hello from bare-metal RISC-V!" end up,
     * along with any constants we define
     */
    .rodata : {
        *(.rodata*)
    } > RAM

    /*
     * .data section, initialized global variables
     * We do not have any right now but when we start storing
     * configuration values they will go here
     */
    .data : {
        *(.data*)
    } > RAM

    /*
     * .got section, Global Offset Table
     * The compiler uses this internally to resolve addresses when we
     * compile with -mcmodel=medany. We need to include it or the
     * linker complains
     */
    .got : {
        *(.got*)
    } > RAM

    /*
     * .bss section, uninitialized global variables
     * __bss_start and __bss_end are symbols that start.S uses to know
     * which memory area needs to be filled with zeros
     */
    .bss : {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        __bss_end = .;
    } > RAM

    /*
     * .stack section, reserved space for the stack
     * NOLOAD means it does not take up space in the ELF file,
     * it only reserves space in memory
     * 0x10000 = 64 KB of stack, more than enough for our firmware
     * __stack_top ends up pointing to the top, which is where
     * start.S initializes the stack pointer
     */
    .stack (NOLOAD) : {
        . = . + 0x10000;
        __stack_top = .;
    } > RAM

    /*
     * Sections we throw away
     * These are meant for executables that run on top of an OS
     * with a dynamic linker. In bare-metal we have no use for them
     */
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
