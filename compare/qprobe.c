/* qprobe.c
 *
 * Ventana de retiro del contador de stores enteros.
 *
 * Mide cuantas instrucciones hacen falta entre el ultimo store y el
 * csrr que lee el contador, para que ese store ya este contado.
 *
 * qemu-ccore cuenta al emitir, asi que deberia dar 3 en todas las filas.
 * La U74 cuenta al retirar, asi que deberia arrancar en 2 y subir a 3.
 *
 * Se compila con el mismo patron que qst.c. El evento se elige con -D:
 *
 *   qemu-ccore   -DSTORE_EVENT=0xF1UL
 *   U74 hart     -DSTORE_EVENT=0x400UL
 */

#define UART0 0x10000000UL
static void uart_putc(char c){*(volatile unsigned char*)UART0=c;}
static void uart_puts(const char*s){while(*s){if(*s=='\n')uart_putc('\r');uart_putc(*s++);}}
static void uart_dec(unsigned long v){char b[24];int n=0;if(!v){uart_putc('0');return;}while(v){b[n++]='0'+v%10;v/=10;}while(n--)uart_putc(b[n]);}

#define WEV(c,v) asm volatile("csrw %0,%1"::"i"(c),"r"((unsigned long)(v)))
#define RC(c)    ({unsigned long _v;asm volatile("csrr %0,%1":"=r"(_v):"i"(c));_v;})

#ifndef STORE_EVENT
#define STORE_EVENT 0xF1UL
#endif

/* volatile, para que los 3 stores sobrevivan a -O2 */
static volatile unsigned long sink;

/* Tres stores, luego N nops, luego la lectura.
 * El .rept lo expande el ensamblador, asi que no agrega stores
 * ni saltos al cuerpo medido. */
#define PROBE(N, LBL) do {                                \
    WEV(0x323, STORE_EVENT); WEV(0xB03, 0);               \
    sink = 1; sink = 2; sink = 3;                         \
    asm volatile(".rept " #N "\n nop\n .endr\n");         \
    unsigned long _s = RC(0xB03);                         \
    uart_puts(LBL); uart_dec(_s); uart_puts("\n");        \
} while (0)

void qmain(void)
{
    /* habilitar el contador 3, igual que hace qst.c */
    unsigned long inh;
    asm volatile("csrr %0,0x320":"=r"(inh));
    inh &= ~(1UL<<3);
    asm volatile("csrw 0x320,%0"::"r"(inh));

    uart_puts("\n=== ventana de retiro, 3 stores ===\n");

    PROBE(0,  "nops=0   S=");
    PROBE(1,  "nops=1   S=");
    PROBE(2,  "nops=2   S=");
    PROBE(3,  "nops=3   S=");
    PROBE(4,  "nops=4   S=");
    PROBE(6,  "nops=6   S=");
    PROBE(8,  "nops=8   S=");
    PROBE(12, "nops=12  S=");
    PROBE(16, "nops=16  S=");
    PROBE(32, "nops=32  S=");

    /* control: fence fuerza el drenaje */
    WEV(0x323, STORE_EVENT); WEV(0xB03, 0);
    sink = 1; sink = 2; sink = 3;
    asm volatile("fence");
    unsigned long f = RC(0xB03);
    uart_puts("fence    S="); uart_dec(f); uart_puts("\n");

    /* control: un solo store, para ver si el desfase depende de cuantos */
    WEV(0x323, STORE_EVENT); WEV(0xB03, 0);
    sink = 1;
    unsigned long u = RC(0xB03);
    uart_puts("1 store  S="); uart_dec(u); uart_puts("\n");

    /* control: diez stores */
    WEV(0x323, STORE_EVENT); WEV(0xB03, 0);
    sink=1; sink=2; sink=3; sink=4; sink=5;
    sink=6; sink=7; sink=8; sink=9; sink=10;
    unsigned long d = RC(0xB03);
    uart_puts("10 store S="); uart_dec(d); uart_puts("\n");

    uart_puts("\n=== done ===\n");
    *(volatile unsigned int*)0x100000=0x5555; for(;;);
}
