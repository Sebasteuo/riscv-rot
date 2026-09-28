#define UART0 0x10000000UL
static void uart_putc(char c){*(volatile unsigned char*)UART0=c;}
static void uart_puts(const char*s){while(*s){if(*s=='\n')uart_putc('\r');uart_putc(*s++);}}
static void uart_dec(unsigned long v){char b[24];int n=0;if(!v){uart_putc('0');return;}while(v){b[n++]='0'+v%10;v/=10;}while(n--)uart_putc(b[n]);}

#define WEV(c,v) asm volatile("csrw %0,%1"::"i"(c),"r"((unsigned long)(v)))
#define RC(c)    ({unsigned long _v;asm volatile("csrr %0,%1":"=r"(_v):"i"(c));_v;})

extern void init_crc32(void);
extern int  body_crc32(unsigned,unsigned);
extern void init_heap_beebs(void*,unsigned long);
static unsigned char heap[8192] __attribute__((aligned(16)));

static void run_one(unsigned gsf)
{
    unsigned long l,s,b,j;
    init_crc32();
    /* six counters, so all four events in one pass, no reprogramming */
    WEV(0x323,0xF0); WEV(0x324,0xF1); WEV(0x325,0xF6); WEV(0x326,0xF3);
    WEV(0xB03,0); WEV(0xB04,0); WEV(0xB05,0); WEV(0xB06,0);
    body_crc32(1,gsf);
    l=RC(0xB03); s=RC(0xB04); b=RC(0xB05); j=RC(0xB06);
    uart_puts("crc32 g");uart_dec(gsf);uart_puts("  ");
    uart_puts("load=");uart_dec(l);uart_puts(" store=");uart_dec(s);
    uart_puts(" branch=");uart_dec(b);uart_puts(" jalr=");uart_dec(j);uart_puts("\n");
}

void qmain(void)
{
    unsigned long inh;
    asm volatile("csrr %0,0x320":"=r"(inh));
    inh &= ~((1UL<<3)|(1UL<<4)|(1UL<<5)|(1UL<<6));
    asm volatile("csrw 0x320,%0"::"r"(inh));
    uart_puts("\n=== crc32 on qemu-ccore, four architectural events ===\n\n");
    init_heap_beebs(heap,sizeof(heap));
    run_one(1); run_one(2); run_one(3);
    uart_puts("\n=== done ===\n");
    *(volatile unsigned int*)0x100000=0x5555;
    for(;;);
}
void *memset(void*s,int c,unsigned long n){unsigned char*p=s;while(n--)*p++=c;return s;}
