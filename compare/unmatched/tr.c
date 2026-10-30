/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */
/*
 * Fifth event: traps.
 *
 * The other four are deterministic points in the instruction stream.
 * A trap is not: it depends on when the exception is taken and how the
 * core handles it. This uses ecall, which raises an exception at a
 * known point, so the count should be the number of ecalls issued.
 *
 * The handler has to return past the ecall, otherwise the program
 * loops on it forever: mepc points at the ecall itself, so it is
 * advanced by four before mret.
 */

#define UART0 0x10010000UL
static void uart_putc(char c){volatile unsigned int*t=(volatile unsigned int*)UART0;while(*t&(1u<<31));*t=(unsigned int)c;}
static void uart_puts(const char*s){while(*s){if(*s=='\n')uart_putc('\r');uart_putc(*s++);}}
static void uart_dec(unsigned long v){char b[24];int n=0;if(!v){uart_putc('0');return;}while(v){b[n++]='0'+v%10;v/=10;}while(n--)uart_putc(b[n]);}

#define WEV(c,v) asm volatile("csrw %0,%1"::"i"(c),"r"((unsigned long)(v)))
#define RC(c)    ({unsigned long _v;asm volatile("csrr %0,%1":"=r"(_v):"i"(c));_v;})
#define MTIME (*(volatile unsigned long *)0x0200BFF8UL)

#define N_ECALLS 1000

/* Minimal M-mode trap handler: step over the ecall and return. */
__attribute__((aligned(4), naked)) static void trap_entry(void)
{
    asm volatile(
        "csrr   t0, mepc\n"
        "addi   t0, t0, 4\n"
        "csrw   mepc, t0\n"
        "mret\n"
    );
}

void fw_main(void)
{
    unsigned long n;
    int i;

    uart_puts("\n=== trap event probe ===\n");

    /*
     * Core clock. The CLINT of this part runs at 1 MHz, so one mtime
     * tick is one microsecond and the quotient is the frequency in MHz.
     */
    {
        unsigned long t0, t1, c0, c1;

        t0 = MTIME;
        while (MTIME == t0) { }
        t0 = MTIME;
        c0 = RC(0xB00);
        while ((MTIME - t0) < 1000000UL) { }
        c1 = RC(0xB00);
        t1 = MTIME;

        uart_puts("mcycle delta   "); uart_dec(c1 - c0); uart_puts("\n");
        uart_puts("mtime delta    "); uart_dec(t1 - t0); uart_puts("\n");
        uart_puts("clock MHz      "); uart_dec((c1 - c0) / (t1 - t0)); uart_puts("\n\n");
    }

    asm volatile("csrw mtvec, %0" :: "r"((unsigned long)trap_entry));

    WEV(0x323, 0x0100UL);   /* U74 class 0, bit 8: exception taken */
    WEV(0xB03, 0);

    for (i = 0; i < N_ECALLS; i++) {
        asm volatile("ecall");
    }

    n = RC(0xB03);

    uart_puts("ecalls issued  "); uart_dec(N_ECALLS); uart_puts("\n");
    uart_puts("counter reads  "); uart_dec(n); uart_puts("\n");

    uart_puts("\n=== done ===\n");
    for(;;) asm volatile("wfi");
}
