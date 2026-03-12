/* ==========================================================================
 * uart.h - Functions for printing through the serial port
 * ==========================================================================
 *
 * Since we are running bare-metal, there is no printf or anything like
 * that available (there is no operating system to give us those things).
 * So we write our own functions to send text to the serial port (UART).
 *
 * The idea is pretty simple. The UART is mapped to a fixed memory
 * address (0x10000000 on the QEMU virt machine). If we write a byte
 * there, QEMU shows it as a character in the terminal. That is all
 * we need to print debug messages and see what is going on.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#ifndef UART_H
#define UART_H

#include <stdint.h>

/*
 * UART0 address on the QEMU virt machine.
 * This is not a random number, it comes from how QEMU defines
 * its memory map for the virt platform.
 */
#define UART0_BASE 0x10000000

/* Send a single character to the UART */
void uart_putc(char c);

/* Send a full null-terminated string to the UART, character by character */
void uart_puts(const char *s);

/*
 * Print a number in hexadecimal format.
 * Super useful for debugging, for example to show memory addresses
 * or register values and check if they look right
 */
void uart_put_hex(uint64_t value);

#endif /* UART_H */
