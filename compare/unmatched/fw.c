/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */

/*
 * Bare-metal firmware for the HiFive Unmatched, loaded by U-Boot SPL
 * in place of OpenSBI.
 *
 * The SPL has already brought up DDR and the clocks by the time this
 * runs, and it hands over in M-mode, which is the whole point: the
 * U74 performance counters are programmed from there and from nowhere
 * else. Linux on this board exposes only cycles and instructions, and
 * a program launched from U-Boot traps on mcycle, so this is the only
 * way to reach them.
 */

#define UART0 0x10010000UL

static void uart_putc(char c)
{
    volatile unsigned int *tx = (volatile unsigned int *)UART0;
    while (*tx & (1u << 31)) { }
    *tx = (unsigned int)c;
}

static void uart_puts(const char *s)
{
    while (*s) {
        if (*s == '\n') uart_putc('\r');
        uart_putc(*s++);
    }
}

static void uart_hex(unsigned long v)
{
    const char *d = "0123456789abcdef";
    int i;
    uart_puts("0x");
    for (i = 60; i >= 0; i -= 4) uart_putc(d[(v >> i) & 0xf]);
}

static void uart_dec(unsigned long v)
{
    char buf[24];
    int n = 0;
    if (!v) { uart_putc('0'); return; }
    while (v) { buf[n++] = '0' + (v % 10); v /= 10; }
    while (n--) uart_putc(buf[n]);
}

#define CSR_R(n) ({ unsigned long _v; asm volatile("csrr %0, " n : "=r"(_v)); _v; })
#define CSR_W(n, v) asm volatile("csrw " n ", %0" :: "r"(v))

void fw_main(void)
{
    unsigned long mhartid, misa, c0, c1, i0, i1;
    unsigned long e3, e4, h3a, h3b, h4a, h4b;
    volatile unsigned long spin;

    uart_puts("\n\n");
    uart_puts("================================================\n");
    uart_puts("  bare-metal firmware, M-mode on the U74\n");
    uart_puts("================================================\n\n");

    mhartid = CSR_R("mhartid");
    misa    = CSR_R("misa");

    uart_puts("mhartid  "); uart_hex(mhartid); uart_puts("\n");
    uart_puts("misa     "); uart_hex(misa);    uart_puts("\n");

    uart_puts("\nmachine CSRs readable, so this really is M-mode.\n\n");


    CSR_W("mhpmevent3", 0x0100UL);
    CSR_W("mhpmevent4", 0x0200UL);

    e3 = CSR_R("mhpmevent3");
    e4 = CSR_R("mhpmevent4");

    uart_puts("mhpmevent3 = "); uart_hex(e3); uart_puts("\n");
    uart_puts("mhpmevent4 = "); uart_hex(e4); uart_puts("\n\n");

    c0  = CSR_R("mcycle");
    i0  = CSR_R("minstret");
    h3a = CSR_R("mhpmcounter3");
    h4a = CSR_R("mhpmcounter4");

    for (spin = 0; spin < 500000; spin++) { }

    c1  = CSR_R("mcycle");
    i1  = CSR_R("minstret");
    h3b = CSR_R("mhpmcounter3");
    h4b = CSR_R("mhpmcounter4");

    uart_puts("over a fixed loop:\n");
    uart_puts("  mcycle       "); uart_dec(c1 - c0);   uart_puts("\n");
    uart_puts("  minstret     "); uart_dec(i1 - i0);   uart_puts("\n");
    uart_puts("  mhpmcounter3 "); uart_dec(h3b - h3a); uart_puts("\n");
    uart_puts("  mhpmcounter4 "); uart_dec(h4b - h4a); uart_puts("\n\n");

    if (e3 == 0 && e4 == 0) {
        uart_puts("the event selectors did not take the write.\n");
    } else if (h3b == h3a && h4b == h4a) {
        uart_puts("events accepted but the counters stayed put.\n");
    } else {
        uart_puts("programmable counters are live.\n");
    }

    uart_puts("\n=== halting ===\n");
    for (;;) { asm volatile("wfi"); }
}
