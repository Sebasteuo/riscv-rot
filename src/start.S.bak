/* ==========================================================================
 * start.S - Bootstrap code for the Root of Trust firmware
 * ==========================================================================
 *
 * Why do we need this file?
 * When a processor powers on, it has nothing set up. No stack, no
 * variables, no idea where anything is. Think of it like turning on
 * a completely empty computer. Someone has to do the dirty work of
 * setting everything up before C code can run. That someone is this file.
 *
 * What does it do step by step?
 *   1. Disables interrupts so nothing bothers us during setup
 *   2. Sets up the stack pointer (sp), which is the register that tells
 *      the processor where to store temporary data. Without this,
 *      no C function can work at all
 *   3. Clears the BSS section. This is the memory area where global
 *      variables without an initial value live. The C standard says
 *      they must start at zero, so we fill that area with zeros
 *   4. Jumps to the main() function written in C
 *   5. If main() ever returns (which should never happen in firmware),
 *      the processor stays in an infinite loop doing nothing
 *
 * What is the execution context here?
 * This code runs in Machine mode (M-mode), the highest privilege level
 * in RISC-V. Here we have full control over the hardware, we can touch
 * any register, any memory region, everything. Later on, our firmware
 * will use this power to configure memory protection (PMP) and then
 * drop user code down to a lower privilege level where it can no longer
 * touch the secrets.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

/*
 * We tell the assembler to place this code in the .text.init section.
 * In our linker script (virt.ld), this section is mapped to the very
 * beginning of RAM (address 0x80000000), so it is the first thing
 * the processor executes when it boots up
 */
.section .text.init

/*
 * Make _start visible to the linker. Without this, the linker would
 * not be able to find our entry point. In virt.ld we use ENTRY(_start)
 * which basically says "program execution begins at _start"
 */
.global _start

_start:
    /*
     * csrw mie, zero
     *
     * CSR stands for Control and Status Register, these are special
     * registers in the processor that control how it behaves. They
     * are separate from regular registers like t0 or sp.
     *
     * mie is the Machine Interrupt Enable CSR. It controls which
     * interrupts are active. If a bit is set to 1, that interrupt
     * is enabled.
     *
     * zero is a special RISC-V register that always reads as 0,
     * no matter what you write to it.
     *
     * So what we are doing here is writing 0 to mie, which turns OFF
     * all interrupts. We do this because during boot we do not want
     * anything interrupting us while we set up the stack and clear memory.
     */
    csrw mie, zero

    /*
     * la sp, __stack_top
     *
     * la stands for Load Address, it is a pseudo-instruction (the
     * assembler converts it into real instructions). It loads a
     * memory address into a register.
     *
     * sp is the Stack Pointer register, it points to the top of
     * the stack.
     *
     * __stack_top is a symbol defined in our linker script (virt.ld).
     * It points to the highest address of the area we reserved for
     * the stack.
     *
     * Why do we need the stack?
     * Every time a C function runs, it needs a place to store its
     * local variables, the parameters it receives, and the return
     * address to go back to when it finishes. That place is the stack.
     *
     * In RISC-V the stack grows downward (from high addresses to low),
     * which is why we initialize it at the top.
     */
    la sp, __stack_top

    /*
     * BSS clearing
     *
     * BSS stands for Block Started by Symbol (a historical name from
     * the early assemblers in the 1950s).
     *
     * What lives in BSS?
     * All global variables that the programmer declared without giving
     * them an initial value. For example:
     *     int counter;        goes to BSS (no value assigned)
     *     int total = 100;    does NOT go to BSS (has a value, goes to .data)
     *
     * The C standard guarantees these variables start at 0. But in
     * bare-metal nobody gives us that guarantee, RAM can have garbage
     * data in it. So we manually walk through the entire BSS area
     * writing zeros.
     *
     * __bss_start and __bss_end are symbols that the linker script
     * defines automatically to mark where BSS begins and ends.
     */
    la t0, __bss_start       /* t0 points to the beginning of BSS */
    la t1, __bss_end         /* t1 points to the end of BSS */

bss_clear:
    /* if t0 has reached t1 (or passed it), we are done cleaning */
    bge t0, t1, bss_done

    /* sd = Store Doubleword, writes 8 bytes (64 bits) of zeros
       at the address t0 points to. We use 8 bytes because this
       is a 64-bit processor */
    sd zero, 0(t0)

    /* move the pointer forward by 8 bytes to clean the next chunk */
    addi t0, t0, 8

    /* go back to the top of the loop */
    j bss_clear

bss_done:
    /*
     * jal = Jump And Link
     * It does two things at once:
     *   1. Saves the address of the next instruction (hang) into
     *      the ra (return address) register
     *   2. Jumps to the main() function
     *
     * When main() executes ret (return), the processor reads ra
     * and comes back here, to the hang instruction right below.
     *
     * From this point on, control passes to C code (main.c)
     */
    jal main

    /*
     * Safety infinite loop
     *
     * If for some reason main() returns (which should never happen
     * in firmware), we get stuck here forever.
     *
     * wfi = Wait For Interrupt, it tells the processor "there is
     * nothing to do, go into low power mode until an interrupt
     * arrives"
     *
     * But since we disabled all interrupts at the beginning with
     * csrw mie, zero, no interrupt will ever arrive and the
     * processor stays asleep forever.
     *
     * The j hang is just in case some spurious event wakes the
     * processor up, so it goes right back to wfi
     */
hang:
    wfi
    j hang
