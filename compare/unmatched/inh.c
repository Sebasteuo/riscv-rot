/*
 * Does mcountinhibit stop the programmable counters on the U74?
 *
 * The comparison harness only ever clears the inhibit bits, which is
 * what lets the counters run, so it never showed whether setting them
 * has any effect. This sets them, reads the register back, and counts
 * a known workload with the bits set and with them clear.
 *
 * Three outcomes are possible and they are not the same thing:
 *   readback 0x18 and the counts stop  -> implemented and working
 *   readback 0x18 and the counts run   -> implemented, no effect
 *   readback 0                         -> the bits are hardwired to zero
 */
#define UART0 0x10010000UL
static void uart_putc(char c){volatile unsigned int*t=(volatile unsigned int*)UART0;while(*t&(1u<<31));*t=(unsigned int)c;}
static void uart_puts(const char*s){while(*s){if(*s==0x0a)uart_putc(0x0d);uart_putc(*s++);}}
static void uart_dec(unsigned long v){char b[24];int n=0;if(!v){uart_putc(0x30);return;}while(v){b[n++]=0x30+v%10;v/=10;}while(n--)uart_putc(b[n]);}
static void uart_hex(unsigned long v){const char*d="0123456789abcdef";int i;uart_puts("0x");for(i=28;i>=0;i-=4)uart_putc(d[(v>>i)&0xf]);}

#define WEV(c,v) asm volatile("csrw %0,%1"::"i"(c),"r"((unsigned long)(v)))
#define RC(c)    ({unsigned long _v;asm volatile("csrr %0,%1":"=r"(_v):"i"(c));_v;})

#define INHIBIT 0x320UL
#define EVENT3  0x323UL
#define EVENT4  0x324UL
#define COUNT3  0xB03UL
#define COUNT4  0xB04UL

#define STORE_EVENT 0x400UL   /* U74: integer store retired */
#define LOAD_EVENT  0x200UL   /* U74: integer load retired */

static volatile unsigned long sink[4];

static void work(void)
{
    int i;
    for (i = 0; i < 1000; i++) {
        sink[0] = (unsigned long)i;
        sink[1] = sink[0];
    }
}

static void run(const char *label)
{
    unsigned long s, l;

    WEV(COUNT3, 0);
    WEV(COUNT4, 0);
    work();
    s = RC(COUNT3);
    l = RC(COUNT4);

    uart_puts(label);
    uart_puts("  stores ");
    uart_dec(s);
    uart_puts("   loads ");
    uart_dec(l);
    uart_puts("\n");
}

void fw_main(void)
{
    unsigned long entry, all, set;

    uart_puts("\n=== mcountinhibit on the U74 ===\n\n");

    entry = RC(INHIBIT);
    uart_puts("value at entry             ");
    uart_hex(entry);
    uart_puts("\n");

    WEV(EVENT3, STORE_EVENT);
    WEV(EVENT4, LOAD_EVENT);

    WEV(INHIBIT, ~0UL);
    all = RC(INHIBIT);
    uart_puts("after writing all ones     ");
    uart_hex(all);
    uart_puts("\n");

    WEV(INHIBIT, (1UL << 3) | (1UL << 4));
    set = RC(INHIBIT);
    uart_puts("after setting bits 3 and 4 ");
    uart_hex(set);
    uart_puts("\n\n");

    WEV(INHIBIT, 0);
    run("bits clear      :");

    WEV(INHIBIT, (1UL << 3) | (1UL << 4));
    run("bits set        :");

    WEV(INHIBIT, 0);
    run("bits clear again:");

    uart_puts("\n=== done ===\n");
    for(;;) asm volatile("wfi");
}
