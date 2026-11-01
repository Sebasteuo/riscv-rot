/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */
/*
 * How long the Stage-1 signature check takes, on silicon.
 *
 * The boot path spends 64,579,455 of its 66,738,034 retired instructions
 * inside this one call. The emulator counts those instructions but is not
 * cycle accurate, and the Stage-1 never ran on this board, so the boot time
 * was never measured here. This puts the dominant part of it in cycles on a
 * U74, which is the unit that survives a change of clock frequency.
 *
 * tweetnacl.o is linked exactly as the Stage-1 builds it.
 */
#include "tweetnacl.h"
#include "sigvec.h"

#define UART0 0x10010000UL
static void uart_putc(char c){volatile unsigned int*t=(volatile unsigned int*)UART0;while(*t&(1u<<31));*t=(unsigned int)c;}
static void uart_puts(const char*s){while(*s){if(*s=='\n')uart_putc('\r');uart_putc(*s++);}}
static void uart_dec(unsigned long v){char b[24];int n=0;if(!v){uart_putc('0');return;}while(v){b[n++]='0'+v%10;v/=10;}while(n--)uart_putc(b[n]);}
#define RC(c) ({unsigned long _v;asm volatile("csrr %0,%1":"=r"(_v):"i"(c));_v;})
#define MTIME (*(volatile unsigned long *)0x0200BFF8UL)

/* TweetNaCl declares this for signing. Verification never calls it. */
void randombytes(unsigned char *p, unsigned long long n){(void)p;(void)n;}

#define N 4
static unsigned char sm[96], out[96];

void fw_main(void)
{
    unsigned long c0,c1,i0,i1,t0,t1;
    unsigned long long olen; int k, rc=-1;

    uart_puts("\n=== Stage-1 signature check on U74 ===\n\n");
    for (k=0;k<64;k++) sm[k]=SV_SIG[k];
    for (k=0;k<32;k++) sm[64+k]=SV_DIG[k];

    t0=MTIME; while(MTIME==t0){}
    t0=MTIME; c0=RC(0xB00);
    while((MTIME-t0)<1000000UL){}
    c1=RC(0xB00); t1=MTIME;
    uart_puts("clock MHz      "); uart_dec((c1-c0)/(t1-t0)); uart_puts("\n\n");

    c0=RC(0xB00); i0=RC(0xB02); t0=MTIME;
    for (k=0;k<N;k++) rc=crypto_sign_open(out,&olen,sm,sizeof sm,SV_PK);
    c1=RC(0xB00); i1=RC(0xB02); t1=MTIME;

    uart_puts("calls          "); uart_dec(N); uart_puts("\n");
    uart_puts("cycles/call    "); uart_dec((c1-c0)/N); uart_puts("\n");
    uart_puts("instrs/call    "); uart_dec((i1-i0)/N); uart_puts("\n");
    uart_puts("us/call        "); uart_dec((t1-t0)/N); uart_puts("\n");
    uart_puts("valid          "); uart_dec((unsigned long)(rc==0)); uart_puts("\n");
    while(1){}
}
