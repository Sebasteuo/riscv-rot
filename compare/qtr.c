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

#define UART0 0x10000000UL
static void uart_putc(char c){*(volatile unsigned char*)UART0=c;}
static void uart_puts(const char*s){while(*s){if(*s=='\n')uart_putc('\r');uart_putc(*s++);}}
static void uart_dec(unsigned long v){char b[24];int n=0;if(!v){uart_putc('0');return;}while(v){b[n++]='0'+v%10;v/=10;}while(n--)uart_putc(b[n]);}

#define WEV(c,v) asm volatile("csrw %0,%1"::"i"(c),"r"((unsigned long)(v)))
#define RC(c)    ({unsigned long _v;asm volatile("csrr %0,%1":"=r"(_v):"i"(c));_v;})

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

void qmain(void)
{
    unsigned long n, inh;
    asm volatile("csrr %0,0x320":"=r"(inh));
    inh &= ~(1UL<<3);
    asm volatile("csrw 0x320,%0"::"r"(inh));
    int i;

    uart_puts("\n=== trap event probe ===\n");

    asm volatile("csrw mtvec, %0" :: "r"((unsigned long)trap_entry));

    WEV(0x323, 0xF4UL);   /* U74 class 0, bit 8: exception taken */
    WEV(0xB03, 0);

    for (i = 0; i < N_ECALLS; i++) {
        asm volatile("ecall");
    }

    n = RC(0xB03);

    uart_puts("ecalls issued  "); uart_dec(N_ECALLS); uart_puts("\n");
    uart_puts("counter reads  "); uart_dec(n); uart_puts("\n");

    uart_puts("\n=== done ===\n");
    *(volatile unsigned int*)0x100000=0x5555; for(;;);
}
