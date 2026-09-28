/*
 * Isolating the one-store offset.
 *
 * Three stores, nothing else, counted on both sides. qemu-ccore counts
 * a store when gen_store emits it, and the U74 counts it at retirement. If
 * that is the whole story, the emulator reports one more than the core
 * does, because the csrr that reads the counter follows a store that
 * has been emitted but not yet retired.
 */
#define UART0 0x10000000UL
static void uart_putc(char c){*(volatile unsigned char*)UART0=c;}
static void uart_puts(const char*s){while(*s){if(*s=='\n')uart_putc('\r');uart_putc(*s++);}}
static void uart_dec(unsigned long v){char b[24];int n=0;if(!v){uart_putc('0');return;}while(v){b[n++]='0'+v%10;v/=10;}while(n--)uart_putc(b[n]);}

#define WEV(c,v) asm volatile("csrw %0,%1"::"i"(c),"r"((unsigned long)(v)))
#define RC(c)    ({unsigned long _v;asm volatile("csrr %0,%1":"=r"(_v):"i"(c));_v;})

static volatile unsigned long sink[4];

void qmain(void)
{
    unsigned long n, inh;
    asm volatile("csrr %0,0x320":"=r"(inh));
    inh &= ~(1UL<<3);
    asm volatile("csrw 0x320,%0"::"r"(inh));

    uart_puts("\n=== store offset probe ===\n");

    WEV(0x323, 0xF1UL);   /* U74: integer store retired */
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
    *(volatile unsigned int*)0x100000=0x5555; for(;;);
}
