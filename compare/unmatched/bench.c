/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */
/*
 * Counter comparison against QEMU on real U74 silicon.
 *
 * Links the very same crc32 and beebsc objects the riscv-rot platform
 * builds, so the instruction stream is identical byte for byte. Only
 * the event codes differ: the U74 numbers here, the 0xFx numbers in
 * qemu-ccore. If an architectural event is what its name says, the
 * counts must match, not merely track.
 *
 * The measured window is exactly the platform's: init runs outside it,
 * body_crc32(1, gsf) runs inside it, for gsf 1, 2 and 3.
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
    while (*s) { if (*s=='\n') uart_putc('\r'); uart_putc(*s++); }
}
static void uart_dec(unsigned long v)
{
    char b[24]; int n=0;
    if(!v){uart_putc('0');return;}
    while(v){b[n++]='0'+(v%10);v/=10;}
    while(n--)uart_putc(b[n]);
}

#define CSR_W(n,v) asm volatile("csrw " n ", %0"::"r"(v))
#define CSR_R(n)   ({unsigned long _v;asm volatile("csrr %0, " n:"=r"(_v));_v;})

/* U74 event selectors: class 0 in the low byte, event bit above it. */
#define U74_LOAD    0x0200UL   /* bit 9  integer load retired    */
#define U74_STORE   0x0400UL   /* bit 10 integer store retired   */
#define U74_BRANCH  0x4000UL   /* bit 14 conditional branch retired */
#define U74_JALR    0x10000UL  /* bit 16 JALR retired            */

/* From the linked embench objects. */
extern void init_crc32(void);
extern int  body_crc32(unsigned lsf, unsigned gsf);
extern void init_heap_beebs(void *heap, unsigned long size);

/* crc32 needs a heap. The platform gives it one this size. */
static unsigned char heap[8192] __attribute__((aligned(16)));

static void run_one(unsigned gsf)
{
    unsigned long l0,l1,s0,s1,b0,b1,j0,j1;

    /* Only two programmable counters, so two events per pass. The
       workload is deterministic, so two passes compose cleanly. */

    /* pass A: load and store */
    init_crc32();
    CSR_W("mhpmevent3", U74_LOAD);
    CSR_W("mhpmevent4", U74_STORE);
    l0=CSR_R("mhpmcounter3"); s0=CSR_R("mhpmcounter4");
    body_crc32(1, gsf);
    l1=CSR_R("mhpmcounter3"); s1=CSR_R("mhpmcounter4");

    /* pass B: branch and jalr */
    init_crc32();
    CSR_W("mhpmevent3", U74_BRANCH);
    CSR_W("mhpmevent4", U74_JALR);
    b0=CSR_R("mhpmcounter3"); j0=CSR_R("mhpmcounter4");
    body_crc32(1, gsf);
    b1=CSR_R("mhpmcounter3"); j1=CSR_R("mhpmcounter4");

    uart_puts("crc32 g"); uart_dec(gsf); uart_puts("  ");
    uart_puts("load="); uart_dec(l1-l0);
    uart_puts(" store="); uart_dec(s1-s0);
    uart_puts(" branch="); uart_dec(b1-b0);
    uart_puts(" jalr="); uart_dec(j1-j0);
    uart_puts("\n");
}

void fw_main(void)
{
    uart_puts("\n=== crc32 on U74, four architectural events ===\n\n");

    init_heap_beebs(heap, sizeof(heap));

    run_one(1);
    run_one(2);
    run_one(3);

    uart_puts("\n=== done ===\n");
    for(;;) asm volatile("wfi");
}

/* crc32's heap allocator needs memset. The platform's board.c provides
   it, but that file also drags in the attestation window hooks, which
   have no place here. A local copy keeps the link self-contained. */
void *memset(void *s, int c, unsigned long n)
{
    unsigned char *p = s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}
