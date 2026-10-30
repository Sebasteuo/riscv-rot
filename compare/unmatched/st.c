/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */
/*
 * Isolating the one-store offset.
 *
 * Three stores, nothing else, counted on both sides. qemu-ccore counts
 * a store when gen_store emits it; the U74 counts it at retirement. If
 * that is the whole story, the emulator reports one more than the core
 * does, because the csrr that reads the counter follows a store that
 * has been emitted but not yet retired.
 */
#define UART0 0x10010000UL
static void uart_putc(char c){volatile unsigned int*t=(volatile unsigned int*)UART0;while(*t&(1u<<31));*t=(unsigned int)c;}
static void uart_puts(const char*s){while(*s){if(*s=='\n')uart_putc('\r');uart_putc(*s++);}}
static void uart_dec(unsigned long v){char b[24];int n=0;if(!v){uart_putc('0');return;}while(v){b[n++]='0'+v%10;v/=10;}while(n--)uart_putc(b[n]);}

#define WEV(c,v) asm volatile("csrw %0,%1"::"i"(c),"r"((unsigned long)(v)))
#define RC(c)    ({unsigned long _v;asm volatile("csrr %0,%1":"=r"(_v):"i"(c));_v;})

static volatile unsigned long sink[4];

void fw_main(void)
{
    unsigned long n;

    uart_puts("\n=== store offset probe ===\n");

    WEV(0x323, 0x0400UL);   /* U74: integer store retired */
    WEV(0xB03, 0);

    /* exactly three stores, volatile so none is elided */
    sink[0] = 1;
    sink[1] = 2;
    sink[2] = 3;

    n = RC(0xB03);

    uart_puts("three stores issued, counter reads ");
    uart_dec(n);
    uart_puts("\n");
    uart_puts("(qemu-ccore should report one more than this)\n");
    uart_puts("\n=== done ===\n");
    for(;;) asm volatile("wfi");
}
