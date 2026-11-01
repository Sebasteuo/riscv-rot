/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */
/*
 * What the attestation service costs per window, on silicon.
 *
 * The emulator counts 90,604 retired instructions per window: 1,243 in the
 * counter reads, 297 in the classifier and the rest in the report MAC. The
 * classifier was already measured here at 355 cycles. This measures the
 * other two blocks in cycles on a U74, so the whole service can be stated
 * in time at the clock this board actually runs.
 *
 * hmac.o and sha256.o are linked exactly as the firmware builds them.
 */
#include "keygen.h"

#define UART0 0x10010000UL
static void uart_putc(char c){volatile unsigned int*t=(volatile unsigned int*)UART0;while(*t&(1u<<31));*t=(unsigned int)c;}
static void uart_puts(const char*s){while(*s){if(*s=='\n')uart_putc('\r');uart_putc(*s++);}}
static void uart_dec(unsigned long v){char b[24];int n=0;if(!v){uart_putc('0');return;}while(v){b[n++]='0'+v%10;v/=10;}while(n--)uart_putc(b[n]);}
#define RC(c) ({unsigned long _v;asm volatile("csrr %0,%1":"=r"(_v):"i"(c));_v;})
#define MTIME (*(volatile unsigned long *)0x0200BFF8UL)

#define NH 64
#define NR 10000

static unsigned char ek[32], report[64], mac[32];
static volatile unsigned long sink;

void fw_main(void)
{
    unsigned long c0,c1,i0,i1,t0,t1;
    unsigned long base[6], now[6], d[6];
    int k,j;

    uart_puts("\n=== Attestation service cost on U74 ===\n\n");
    for (k=0;k<32;k++) ek[k]=(unsigned char)(k*7+1);
    for (k=0;k<64;k++) report[k]=(unsigned char)(k*3+5);

    t0=MTIME; while(MTIME==t0){}
    t0=MTIME; c0=RC(0xB00);
    while((MTIME-t0)<1000000UL){}
    c1=RC(0xB00); t1=MTIME;
    uart_puts("clock MHz          "); uart_dec((c1-c0)/(t1-t0)); uart_puts("\n\n");

    c0=RC(0xB00); i0=RC(0xB02);
    for (k=0;k<NH;k++) hmac_sha256(ek,32,report,64,mac);
    c1=RC(0xB00); i1=RC(0xB02);
    uart_puts("mac calls          "); uart_dec(NH); uart_puts("\n");
    uart_puts("mac cycles/call    "); uart_dec((c1-c0)/NH); uart_puts("\n");
    uart_puts("mac instrs/call    "); uart_dec((i1-i0)/NH); uart_puts("\n");
    sink += mac[0];

    for (j=0;j<6;j++) base[j]=0;
    c0=RC(0xB00); i0=RC(0xB02);
    for (k=0;k<NR;k++){
        now[0]=RC(0xB03); now[1]=RC(0xB04); now[2]=RC(0xB03);
        now[3]=RC(0xB04); now[4]=RC(0xB03); now[5]=RC(0xB04);
        for (j=0;j<6;j++) d[j]=now[j]-base[j];
        sink += d[0]+d[5];
    }
    c1=RC(0xB00); i1=RC(0xB02);
    uart_puts("\nread rounds        "); uart_dec(NR); uart_puts("\n");
    uart_puts("read cycles/round  "); uart_dec((c1-c0)/NR); uart_puts("\n");
    uart_puts("read instrs/round  "); uart_dec((i1-i0)/NR); uart_puts("\n");

    uart_puts("\nsink               "); uart_dec(sink); uart_puts("\n");
    while(1){}
}
