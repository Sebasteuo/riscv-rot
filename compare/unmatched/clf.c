/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */
/*
 * How long the in-device verdict takes, on silicon.
 *
 * The emulator puts classification at 188 microseconds per window, but
 * QEMU is not cycle accurate and that figure carries no weight on its
 * own. Here it is measured in cycles on a U74, which is the unit that
 * survives a change of clock frequency.
 *
 * profile.o is linked exactly as the platform builds it, so the
 * arithmetic executed is the same.
 */

#define UART0 0x10010000UL
static void uart_putc(char c){volatile unsigned int*t=(volatile unsigned int*)UART0;while(*t&(1u<<31));*t=(unsigned int)c;}
static void uart_puts(const char*s){while(*s){if(*s=='\n')uart_putc('\r');uart_putc(*s++);}}
static void uart_dec(unsigned long v){char b[24];int n=0;if(!v){uart_putc('0');return;}while(v){b[n++]='0'+v%10;v/=10;}while(n--)uart_putc(b[n]);}

#define RC(c) ({unsigned long _v;asm volatile("csrr %0,%1":"=r"(_v):"i"(c));_v;})
#define MTIME (*(volatile unsigned long *)0x0200BFF8UL)

/* From the platform's profile.o, unchanged. */
typedef int profile_verdict_t;
extern profile_verdict_t profile_check(unsigned int app_id, const unsigned long *d);

#define N 1000

void fw_main(void)
{
    /* A nominal crc32 window and an attack window, from the platform. */
    static const unsigned long nominal[6] = { 1046867, 524115, 174761, 174422, 1, 2 };
    static const unsigned long attack[6]  = {    1565,    698,    336,      5, 1, 2 };

    unsigned long c0, c1, i0, i1;
    volatile profile_verdict_t v = 0;
    int k;

    uart_puts("\n=== classifier cost on U74 ===\n\n");

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

    /* nominal input */
    c0 = RC(0xB00); i0 = RC(0xB02);
    for (k = 0; k < N; k++) v = profile_check(2, nominal);
    c1 = RC(0xB00); i1 = RC(0xB02);

    uart_puts("nominal input, "); uart_dec(N); uart_puts(" calls\n");
    uart_puts("  cycles total      "); uart_dec(c1-c0); uart_puts("\n");
    uart_puts("  cycles per call   "); uart_dec((c1-c0)/N); uart_puts("\n");
    uart_puts("  instrs per call   "); uart_dec((i1-i0)/N); uart_puts("\n");
    uart_puts("  verdict           "); uart_dec((unsigned long)v); uart_puts("\n\n");

    /* attack input: the early exit may make it cheaper */
    c0 = RC(0xB00); i0 = RC(0xB02);
    for (k = 0; k < N; k++) v = profile_check(2, attack);
    c1 = RC(0xB00); i1 = RC(0xB02);

    uart_puts("attack input, "); uart_dec(N); uart_puts(" calls\n");
    uart_puts("  cycles total      "); uart_dec(c1-c0); uart_puts("\n");
    uart_puts("  cycles per call   "); uart_dec((c1-c0)/N); uart_puts("\n");
    uart_puts("  instrs per call   "); uart_dec((i1-i0)/N); uart_puts("\n");
    uart_puts("  verdict           "); uart_dec((unsigned long)v); uart_puts("\n");

    uart_puts("\n=== done ===\n");
    for(;;) asm volatile("wfi");
}

void *memset(void*s,int c,unsigned long n){unsigned char*p=s;while(n--)*p++=c;return s;}
