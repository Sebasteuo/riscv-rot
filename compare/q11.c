/*
 * Eleven-benchmark cross-check on real U74 silicon.
 *
 * Same objects, same measured window as the platform: init outside,
 * body(lsf, gsf) inside, for gsf 1, 2, 3. Four events read in two
 * passes because the U74 has only two programmable counters, which is
 * sound here since the workloads are deterministic.
 */

#define UART0 0x10000000UL
static void uart_putc(char c){*(volatile unsigned char*)UART0=c;}
static void uart_puts(const char*s){while(*s){if(*s=='\n')uart_putc('\r');uart_putc(*s++);}}
static void uart_dec(unsigned long v){char b[24];int n=0;if(!v){uart_putc('0');return;}while(v){b[n++]='0'+v%10;v/=10;}while(n--)uart_putc(b[n]);}
static void pad(const char*s,int w){int n=0;const char*p=s;while(*p++)n++;uart_puts(s);while(n++<w)uart_putc(' ');}

#define WEV(c,v) asm volatile("csrw %0,%1"::"i"(c),"r"((unsigned long)(v)))
#define RC(c)    ({unsigned long _v;asm volatile("csrr %0,%1":"=r"(_v):"i"(c));_v;})

#define U_LOAD   0xF0UL
#define U_STORE  0xF1UL
#define U_BRANCH 0xF6UL
#define U_JALR   0xF3UL

extern void init_heap_beebs(void*,unsigned long);

typedef void (*initfn)(void);
typedef int  (*bodyfn)(unsigned,unsigned);

extern void init_aha_mont64(void); extern int body_aha_mont64(unsigned,unsigned);
extern void init_crc32(void);       extern int body_crc32(unsigned,unsigned);
extern void init_depthconv(void);   extern int body_depthconv(unsigned,unsigned);
extern void init_edn(void);         extern int body_edn(unsigned,unsigned);
extern void init_huffbench(void);   extern int body_huffbench(unsigned,unsigned);
extern void init_matmult_int(void); extern int body_matmult_int(unsigned,unsigned);
extern void init_md5sum(void);
/* md5sum's body takes a third argument, the message length. The
   platform declares it with two and gets away with it under QEMU;
   on silicon the leftover register value makes len huge, malloc
   returns NULL and md5 memcpy's through it. Declared correctly
   here and called with the benchmark's own MSG_SIZE. */
extern int body_md5sum(unsigned,unsigned,int);
static int md5_shim(unsigned l,unsigned g){return body_md5sum(l,g,1000);}
extern void init_nettle_aes(void);  extern int body_nettle_aes(unsigned,unsigned);
extern void init_nettle_sha256(void);extern int body_nettle_sha256(unsigned,unsigned);
extern void init_nsichneu(void);    extern int body_nsichneu(unsigned,unsigned);
extern void init_picojpeg(void);    extern int body_picojpeg(unsigned,unsigned);

static const char *names[] = {
  "aha-mont64","crc32","depthconv","edn","huffbench","matmult-int",
  "md5sum","nettle-aes","nettle-sha256","nsichneu","picojpeg"
};
static const initfn inits[] = {
  init_aha_mont64,init_crc32,init_depthconv,init_edn,init_huffbench,
  init_matmult_int,init_md5sum,init_nettle_aes,init_nettle_sha256,
  init_nsichneu,init_picojpeg
};
static const bodyfn bodies[] = {
  body_aha_mont64,body_crc32,body_depthconv,body_edn,body_huffbench,
  body_matmult_int,md5_shim,body_nettle_aes,body_nettle_sha256,
  body_nsichneu,body_picojpeg
};
static const unsigned lsf[] = { 1,170,1,1,1,1,1,1,1,1,1 };

static unsigned char heap[262144] __attribute__((aligned(16)));

static void run(int i, unsigned gsf)
{
    unsigned long l,s,b,j;

    /* six counters here, so all four events in a single pass */
    init_heap_beebs(heap, sizeof(heap));
    inits[i]();
    WEV(0x323,U_LOAD); WEV(0x324,U_STORE);
    WEV(0x325,U_BRANCH); WEV(0x326,U_JALR);
    WEV(0xB03,0); WEV(0xB04,0); WEV(0xB05,0); WEV(0xB06,0);
    bodies[i](lsf[i], gsf);
    l=RC(0xB03); s=RC(0xB04); b=RC(0xB05); j=RC(0xB06);

    pad(names[i],14);
    uart_puts(" g"); uart_dec(gsf); uart_puts("  ");
    uart_puts("L="); uart_dec(l);
    uart_puts(" S="); uart_dec(s);
    uart_puts(" B="); uart_dec(b);
    uart_puts(" J="); uart_dec(j);
    uart_puts("\n");
}

void qmain(void)
{
    int i; unsigned g;
    uart_puts("\n=== eleven benchmarks on qemu-ccore, four events each ===\n\n");
    unsigned long inh; asm volatile("csrr %0,0x320":"=r"(inh));
    inh &= ~((1UL<<3)|(1UL<<4)|(1UL<<5)|(1UL<<6));
    asm volatile("csrw 0x320,%0"::"r"(inh));
    init_heap_beebs(heap, sizeof(heap));
    for (i = 0; i < 11; i++) {
        for (g = 1; g <= 3; g++) run(i, g);
    }
    uart_puts("\n=== done ===\n");
    *(volatile unsigned int*)0x100000=0x5555; for(;;);
}

void *memset(void*s,int c,unsigned long n){unsigned char*p=s;while(n--)*p++=c;return s;}
void *memcpy(void*d,const void*s,unsigned long n){unsigned char*a=d;const unsigned char*b=s;while(n--)*a++=*b++;return d;}
int memcmp(const void*a,const void*b,unsigned long n){const unsigned char*x=a,*y=b;while(n--){if(*x!=*y)return *x-*y;x++;y++;}return 0;}
void abort(void){uart_puts("\n[abort]\n");for(;;);}
