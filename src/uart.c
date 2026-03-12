/* ==========================================================================
 * uart.c - Implementation of the UART printing functions
 * ==========================================================================
 *
 * This is where the actual code for the functions declared in uart.h
 * lives. Before this, everything was crammed into main.c but we split
 * it out because main is going to grow a lot when we add PMP, Secure
 * Storage and everything else. Keeps things cleaner this way.
 *
 * The key thing to understand here is how MMIO works.
 * To send a character to the UART, we do not use any special processor
 * instruction. We just write the byte to the memory address 0x10000000
 * and QEMU takes care of showing it in the terminal. Every write to
 * that address equals one character on screen.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#include "uart.h"

/* -------------------------------------------------------------------------
 * uart_putc - Send a single character to the UART
 *
 * What it does is create a pointer to address 0x10000000 and write
 * the character there. That is it.
 *
 * The "volatile" keyword is important here. It tells the compiler
 * "every time I write to this address, actually do it, do not skip it".
 * Without volatile the compiler might think "I already wrote to that
 * address, why would I write again?" and optimize away our writes.
 * But in MMIO every single write matters because it has a real effect
 * on the hardware (or in our case, on QEMU).
 * ------------------------------------------------------------------------- */
void uart_putc(char c)
{
    volatile uint8_t *uart = (volatile uint8_t *)UART0_BASE;
    *uart = c;
}

/* -------------------------------------------------------------------------
 * uart_puts - Send a full string to the UART
 *
 * Walks through the string character by character and calls uart_putc
 * for each one. Stops when it hits the '\0' (the null terminator that
 * marks the end of every string in C).
 * ------------------------------------------------------------------------- */
void uart_puts(const char *s)
{
    while (*s) {
        uart_putc(*s);
        s++;
    }
}

/* -------------------------------------------------------------------------
 * uart_put_hex - Print a number in hexadecimal
 *
 * This is going to be really handy for debugging. When we want to see
 * the value of a register or a memory address, we can call this and it
 * shows something like 0x00000000DEADBEEF for example.
 *
 * How it works: it takes the 64-bit number and converts it 4 bits at a
 * time (one nibble), starting from the highest bits. Each nibble becomes
 * a hex character (0-9 or a-f).
 *
 * The shift and mask trick:
 *   (value >> 60) gives us the top 4 bits
 *   & 0xf keeps only those 4 bits
 *   Then we move down to the next 4 bits with >> 56, >> 52, etc.
 * ------------------------------------------------------------------------- */
void uart_put_hex(uint64_t value)
{
    /* lookup table to convert a nibble (0-15) to its hex character */
    const char hex_chars[] = "0123456789abcdef";
    int i;

    uart_puts("0x");

    /* walk through all 16 nibbles (64 bits / 4 bits per nibble = 16) */
    for (i = 60; i >= 0; i -= 4) {
        uart_putc(hex_chars[(value >> i) & 0xf]);
    }
}
