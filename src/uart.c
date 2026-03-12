/* ==========================================================================

 * uart.c - Implementacion de las funciones para imprimir por UART

 * ==========================================================================

 *

 * Aca esta el codigo real de las funciones que declaramos en uart.h.

 * Antes todo esto estaba metido en main.c, pero lo separamos porque

 * el main va a crecer bastante cuando agreguemos PMP, Secure Storage

 * y todo lo demas. Asi queda mas ordenado.

 *

 * Lo mas importante de entender aca es como funciona MMIO:

 * Para mandar un caracter al UART, no usamos ninguna instruccion

 * especial del procesador. Simplemente escribimos el byte en la

 * direccion de memoria 0x10000000 y QEMU se encarga de mostrarlo

 * en la terminal. Cada escritura en esa direccion = un caracter

 * que aparece en pantalla.

 *

 * Autor: Sebastian Alba

 * Proyecto: Firmware Root of Trust para RISC-V con aislamiento PMP

 * ========================================================================== */

#include "uart.h"

/* -------------------------------------------------------------------------

 * uart_putc - Manda un solo caracter al UART

 *

 * Lo que hace es crear un puntero a la direccion 0x10000000 y escribir

 * el caracter ahi. Nada mas.

 *

 * El keyword "volatile" es importante: le dice al compilador "cada vez

 * que yo escriba en esta direccion, hacelo de verdad, no te lo saltes".

 * Sin volatile, el compilador podria pensar "ya escribi en esa direccion,

 * para que voy a escribir de nuevo?" y eliminar escrituras. Pero en MMIO

 * cada escritura importa porque tiene un efecto real en el hardware.

 * ------------------------------------------------------------------------- */

void uart_putc(char c)

{

    volatile uint8_t *uart = (volatile uint8_t *)UART0_BASE;

    *uart = c;

}

/* -------------------------------------------------------------------------

 * uart_puts - Manda un string completo al UART

 *

 * Recorre el string caracter por caracter y llama a uart_putc para

 * cada uno. Para cuando encuentra el '\0' (el null terminator que

 * marca el final de todo string en C).

 * ------------------------------------------------------------------------- */

void uart_puts(const char *s)

{

    while (*s) {

        uart_putc(*s);

        s++;

    }

}

/* -------------------------------------------------------------------------

 * uart_put_hex - Imprime un numero en hexadecimal

 *

 * Esto nos va a servir mucho para debug. Cuando queramos ver el valor

 * de un registro o una direccion de memoria, podemos llamar esta funcion

 * y nos lo muestra en formato 0x00000000DEADBEEF por ejemplo.

 *

 * Como funciona: agarra el numero de 64 bits y lo va convirtiendo

 * de a 4 bits (un nibble), empezando por los bits mas altos.

 * Cada nibble se convierte en un caracter hex (0-9 o a-f).

 *

 * El shift y la mascara:

 *   - (value >> 60) nos da los 4 bits mas altos

 *   - & 0xf nos deja solo esos 4 bits

 *   - Despues bajamos a los siguientes 4 bits con >> 56, >> 52, etc.

 * ------------------------------------------------------------------------- */

void uart_put_hex(uint64_t value)

{

    /* Tabla para convertir un nibble (0-15) a su caracter hex */

    const char hex_chars[] = "0123456789abcdef";

    int i;

    uart_puts("0x");

    /* Recorremos los 16 nibbles del numero (64 bits / 4 bits = 16 nibbles) */

    for (i = 60; i >= 0; i -= 4) {

        uart_putc(hex_chars[(value >> i) & 0xf]);

    }

}

