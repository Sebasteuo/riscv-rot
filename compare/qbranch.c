/*
 * Does 0xF2 count taken branches and 0xF6 all retired branches?
 *
 * The silicon comparison reads retired conditional branches on the U74,
 * because the core offers no taken event, while the classifier uses the
 * taken one. That substitution is only sound if the two events are in
 * fact different. This program measures the difference.
 *
 * Both events are programmed at the same time, on counters 3 and 4, so
 * one loop gives both numbers and no counter is ever reprogrammed.
 *
 * Two loops, so the answer is checked from both sides:
 *
 *   loop A, an empty counted loop. Nearly every branch is the backward
 *   edge and is taken, so the two counts should come out close together.
 *
 *   loop B, the condition reads a volatile, so the compiler cannot work
 *   out the parity, unroll the loop or fold the body into a conditional
 *   move. Close to half the conditional branches are not taken, so the
 *   retired count should come out above the taken one.
 *
 * Equal counts in loop B would mean 0xF2 is not counting what its name
 * says, and the silicon comparison would need rewording.
 */

#define UART0 0x10000000UL
static void uart_putc(char c){*(volatile unsigned char*)UART0=c;}
static void uart_puts(const char*s){while(*s){if(*s=='\n')uart_putc('\r');uart_putc(*s++);}}
static void uart_dec(unsigned long v){char b[24];int n=0;if(!v){uart_putc('0');return;}while(v){b[n++]='0'+v%10;v/=10;}while(n--)uart_putc(b[n]);}

#define WEV(c,v) asm volatile("csrw %0,%1"::"i"(c),"r"((unsigned long)(v)))
#define RC(c)    ({unsigned long _v;asm volatile("csrr %0,%1":"=r"(_v):"i"(c));_v;})

#define ITERATIONS 1000

/* Read every iteration, so the compiler cannot predict the branch */
static volatile unsigned long gate;

static void show(const char *label, unsigned long taken, unsigned long retired)
{
    uart_puts(label);
    uart_puts("  taken=");
    uart_dec(taken);
    uart_puts("  retired=");
    uart_dec(retired);
    if (retired >= taken) {
        uart_puts("  retired-taken=");
        uart_dec(retired - taken);
    } else {
        uart_puts("  taken-retired=");
        uart_dec(taken - retired);
        uart_puts(" (taken came out higher)");
    }
    uart_puts("\n");
}

void qmain(void)
{
    unsigned long inh;
    unsigned long a_taken, a_retired, b_taken, b_retired;
    unsigned long i;
    volatile unsigned long vi;

    /* This program runs entirely in M-mode, so let the counters advance */
    asm volatile("csrr %0,0x320":"=r"(inh));
    inh &= ~((1UL << 3) | (1UL << 4));
    asm volatile("csrw 0x320,%0"::"r"(inh));

    /* 0xF2 on counter 3, 0xF6 on counter 4, different events so both bind */
    WEV(0x323, 0xF2);
    WEV(0x324, 0xF6);

    uart_puts("\n=== branch taken (0xF2) against branch retired (0xF6) ===\n\n");

    /* ---- loop A, the control: nearly every branch is taken ---- */
    WEV(0xB03, 0);
    WEV(0xB04, 0);
    for (vi = 0; vi < ITERATIONS; vi++) {
        /* empty on purpose, the backward edge is what is measured */
    }
    a_taken = RC(0xB03);
    a_retired = RC(0xB04);

    /* ---- loop B: close to half of the conditional branches are not taken ---- */
    WEV(0xB03, 0);
    WEV(0xB04, 0);
    gate = 0;
    for (i = 0; i < ITERATIONS; i++) {
        if (gate & 1)
            gate = gate + 2;
        gate = gate + 1;
    }
    b_taken = RC(0xB03);
    b_retired = RC(0xB04);

    show("loop A, empty, branches taken  ", a_taken, a_retired);
    show("loop B, half the branches skip ", b_taken, b_retired);

    uart_puts("\n");
    if (b_retired > b_taken && a_retired >= a_taken) {
        uart_puts("the two events are distinct, and 0xF2 does count only\n");
        uart_puts("the branches that are taken\n");
    } else if (b_retired == b_taken) {
        uart_puts("the two counts agree even where branches are skipped, so\n");
        uart_puts("0xF2 is not counting what its name says\n");
    } else {
        uart_puts("unexpected result, read the numbers above\n");
    }

    uart_puts("\n=== done ===\n");
    *(volatile unsigned int*)0x100000 = 0x5555;
    for(;;);
}

void *memset(void*s,int c,unsigned long n){unsigned char*p=s;while(n--)*p++=c;return s;}
