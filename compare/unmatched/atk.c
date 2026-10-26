/*
 * One scenario, one pair of events, one boot.
 *
 * Earlier harnesses ran all five scenarios in a loop and shared state
 * between them. That kept breaking: the diverted paths jump back to a
 * recovery point and skip whatever follows, so results were written
 * twice, or not at all, depending on the path. There is no way to
 * parch around that reliably.
 *
 * This measures one thing per boot. The scenario and the event pair
 * are read from a byte at a fixed address, patched into the image, so
 * ten measurements need one build and ten quick rewrites of that byte.
 * Nothing is shared, nothing can be overwritten.
 */

#define UART0 0x10010000UL
static void uart_putc(char c){volatile unsigned int*t=(volatile unsigned int*)UART0;while(*t&(1u<<31));*t=(unsigned int)c;}
static void uart_puts(const char*s){while(*s){if(*s=='\n')uart_putc('\r');uart_putc(*s++);}}
static void uart_dec(unsigned long v){char b[24];int n=0;if(!v){uart_putc('0');return;}while(v){b[n++]='0'+v%10;v/=10;}while(n--)uart_putc(b[n]);}

#define WEV(c,v) asm volatile("csrw %0,%1"::"i"(c),"r"((unsigned long)(v)))
#define RC(c)    ({unsigned long _v;asm volatile("csrr %0,%1":"=r"(_v):"i"(c));_v;})

#define U_LOAD   0x0200UL
#define U_STORE  0x0400UL
#define U_BRANCH 0x4000UL
#define U_JALR   0x10000UL

/*
 * Config byte, placed first in .data so its offset in the image is
 * predictable. Low nibble selects the scenario, high nibble the event
 * pair: 0 = load/store, 1 = branch/jalr.
 */
__attribute__((section(".data.cfg"), used))
volatile unsigned char cfg = 0x00;

static volatile unsigned long work_sink;
static volatile int diverted;
static volatile int reuse_active;
static unsigned long recover_sp, recover_ra;

/* The one place a measurement is ever written. */
static volatile unsigned long m_a, m_b;
static volatile int have;

static volatile unsigned long base_a, base_b;

/*
 * Snapshot rather than zero. Writing the U74 event counters does not
 * clear them reliably: a probe that zeroed them and then issued eight
 * stores read back thirty-three thousand on one counter. Taking a
 * baseline and subtracting is immune to that.
 */
static void win_open(void)
{
    if ((cfg >> 4) == 0) { WEV(0x323,U_LOAD);   WEV(0x324,U_STORE); }
    else                 { WEV(0x323,U_BRANCH); WEV(0x324,U_JALR);  }
    {
        unsigned long x = RC(0xB03);
        unsigned long y = RC(0xB04);
        base_a = x;
        base_b = y;
    }
    have = 0;
}

static void win_close(void)
{
    unsigned long x, y;

    if (have) return;          /* first close wins, always */

    /*
     * Both counters into registers before anything is stored. m_a and
     * m_b are volatile, so assigning to them is itself a store that
     * the window would otherwise count.
     */
    x = RC(0xB03);
    y = RC(0xB04);

    m_a = x - base_a;
    m_b = y - base_b;
    have = 1;
}

static void __attribute__((noinline)) benign_helper(void)
{
    volatile unsigned int i;
    for (i = 0; i < 16; i++) work_sink += i;

    if (reuse_active) {
        diverted = 1;
        reuse_active = 0;
        win_close();
        asm volatile("ld sp, %0\n ld ra, %1\n jr ra\n"
                     :: "m"(recover_sp), "m"(recover_ra) : "memory");
    }
}

static void __attribute__((noinline)) unreachable_path(void)
{
    volatile unsigned long acc = 0;
    int i;
    diverted = 1;
    for (i = 0; i < 200; i++) acc += (unsigned long)i * 3;
    work_sink = acc;
    win_close();
    asm volatile("ld sp, %0\n ld ra, %1\n jr ra\n"
                 :: "m"(recover_sp), "m"(recover_ra) : "memory");
}

static void __attribute__((noinline))
copy_input(unsigned char *dst, const unsigned char *src, unsigned int n)
{
    unsigned int i;
    for (i = 0; i < n; i++) dst[i] = src[i];
}

static void __attribute__((noinline))
vulnerable(const unsigned char *input, unsigned int len)
{
    unsigned char buffer[32];
    copy_input(buffer, input, len);
    work_sink += buffer[0];
}

static void __attribute__((noinline)) launch(int idx)
{
    unsigned char input[256];
    unsigned long target;
    int i, n;

    asm volatile("mv %0, sp" : "=r"(recover_sp));
    asm volatile("mv %0, ra" : "=r"(recover_ra));

    switch (idx) {
    case 0:  /* none: normal call, no overflow */
        win_open();
        benign_helper();
        for (i = 0; i < 32; i++) input[i] = 0x41;
        vulnerable(input, 32);
        win_close();
        return;

    case 1:  /* small: overflow short of the return address */
        win_open();
        for (i = 0; i < 40; i++) input[i] = 0x41;
        vulnerable(input, 40);
        win_close();
        return;

    case 2: target = (unsigned long)(void *)unreachable_path; n = 64;  break;
    case 3: target = (unsigned long)(void *)unreachable_path; n = 256; break;
    case 4: target = (unsigned long)(void *)benign_helper;    n = 64;
            reuse_active = 1; break;
    default: return;
    }

    win_open();

    for (i = 0; i < n; i++) input[i] = 0x41;
    for (i = 0; i < 8; i++)
        input[40+i] = (unsigned char)((target >> (i*8)) & 0xFF);

    vulnerable(input, n);
    win_close();       /* reached only if the diversion did not happen */
}

static const char *names[] = { "none","small","redirect","long","reuse" };

void fw_main(void)
{
    int idx = cfg & 0x0F;

    /*
     * Explicit initialisation. These live in .bss, which the boot code
     * clears, but the reuse flag in particular decides whether
     * benign_helper takes the diverted path, so leaving it to the
     * loader is not worth the risk: a stray non-zero value makes the
     * nominal scenario divert before the window is even open.
     */
    diverted = 0;
    reuse_active = 0;
    have = 0;
    m_a = 0;
    m_b = 0;
    work_sink = 0;

    uart_puts("\n=== scenario ");
    uart_puts(names[idx]);
    uart_puts((cfg >> 4) == 0 ? "  events load/store" : "  events branch/jalr");
    uart_puts(" ===\n");

    launch(idx);

    /* sanity: two counters, two very different events */
    {
        volatile unsigned long sk[8];
        int q;
        WEV(0x323, U_LOAD); WEV(0x324, U_STORE);
        unsigned long p3, p4, q3, q4;
        p3 = RC(0xB03); p4 = RC(0xB04);
        for (q = 0; q < 8; q++) sk[q] = q;      /* 8 stores, few loads */
        q3 = RC(0xB03); q4 = RC(0xB04);
        /* read first, print after: uart_puts spins on the transmit
           register and would otherwise be counted as thousands of
           loads inside the window */
        uart_puts("  sanity 8 stores: c3="); uart_dec(q3-p3);
        uart_puts(" c4="); uart_dec(q4-p4); uart_puts("\n");
    }

    uart_puts("  ev3="); uart_dec(RC(0x323));
    uart_puts(" ev4="); uart_dec(RC(0x324));
    uart_puts("\n");
    uart_puts("  a="); uart_dec(m_a);
    uart_puts("  b="); uart_dec(m_b);
    uart_puts("  diverted="); uart_dec((unsigned long)diverted);
    uart_puts("\n\n=== done ===\n");
    for(;;) asm volatile("wfi");
}
