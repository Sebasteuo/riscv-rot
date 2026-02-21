/* ==========================================================================
 * main.c - Punto de entrada principal del firmware Root of Trust
 * ==========================================================================
 *
 * Que hace este archivo?
 * ----------------------
 * Aca esta la funcion main(), que es a donde salta el codigo de arranque
 * (start.S) despues de preparar el stack y limpiar el BSS.
 * Por ahora lo unico que hace es imprimir mensajes por el puerto serial
 * (UART) para confirmar que el firmware arranco correctamente.
 *
 * Como funciona la impresion por UART?
 * -------------------------------------
 * En la maquina "virt" de QEMU, el puerto serial (UART) esta mapeado
 * en la direccion de memoria 0x10000000. Esto se llama Memory-Mapped I/O
 * (MMIO), que basicamente significa que para hablar con un dispositivo
 * de hardware, en vez de usar instrucciones especiales, simplemente
 * escribimos en una direccion de memoria especifica.
 *
 * Entonces para imprimir la letra A, literalmente escribimos el byte 0x41
 * (que es A en ASCII) en la direccion 0x10000000. QEMU intercepta esa
 * escritura y la muestra en la terminal. Asi de directo es bare-metal.
 *
 * Que viene despues?
 * ------------------
 * En las siguientes fases vamos a agregar aca la configuracion de PMP,
 * la inicializacion del Secure Storage, la generacion de llaves y todo
 * lo que necesita el Root of Trust. Pero primero hay que asegurarse de
 * que el arranque basico funciona bien, y eso es lo que estamos probando.
 *
 * Autor: Sebastian Alba
 * Proyecto: Firmware Root of Trust para RISC-V con aislamiento PMP
 * ========================================================================== */

#include <stdint.h>

/* -------------------------------------------------------------------------
 * Direccion base del UART0 en la maquina virt de QEMU
 *
 * Este valor no es inventado, viene de la especificacion de la maquina
 * "virt" de QEMU. Cada maquina virtual tiene un mapa de memoria fijo
 * donde los dispositivos estan ubicados en direcciones especificas.
 * El UART (Universal Asynchronous Receiver-Transmitter) es el dispositivo
 * que nos permite enviar y recibir datos por el puerto serial.
 *
 * 0x10000000 es donde QEMU pone el primer UART en la maquina virt.
 * ------------------------------------------------------------------------- */
#define UART0_BASE 0x10000000

/* -------------------------------------------------------------------------
 * uart_putc - Escribe un solo caracter al puerto serial
 *
 * Parametros:
 *   c - El caracter que queremos imprimir
 *
 * Como funciona:
 *   1. Creamos un puntero que apunta a la direccion del UART (0x10000000)
 *   2. Escribimos el caracter en esa direccion
 *   3. QEMU detecta la escritura y muestra el caracter en la terminal
 *
 * Por que usamos volatile?
 *   Porque le decimos al compilador "no optimices los accesos a esta
 *   direccion". Sin volatile, el compilador podria pensar que escribir
 *   varias veces en la misma direccion es redundante y eliminar
 *   escrituras. Pero en MMIO cada escritura tiene un efecto real en
 *   el hardware (o en este caso, en QEMU).
 * ------------------------------------------------------------------------- */
void uart_putc(char c)
{
    volatile uint8_t *uart = (volatile uint8_t *)UART0_BASE;
    *uart = c;
}

/* -------------------------------------------------------------------------
 * uart_puts - Escribe una cadena completa al puerto serial
 *
 * Parametros:
 *   s - Puntero a la cadena de texto (terminada en null, como toda
 *       cadena en C)
 *
 * Recorre la cadena caracter por caracter y usa uart_putc para
 * imprimir cada uno. Se detiene cuando encuentra el caracter null
 * (el \0 que marca el final de toda cadena en C).
 * ------------------------------------------------------------------------- */
void uart_puts(const char *s)
{
    while (*s) {
        uart_putc(*s);
        s++;
    }
}

/* -------------------------------------------------------------------------
 * main - Funcion principal del firmware
 *
 * Aca es donde empieza la logica real del firmware. Por ahora solo
 * imprimimos mensajes de confirmacion para verificar que:
 *   - El procesador arranco correctamente en M-mode
 *   - El UART funciona y podemos ver la salida
 *   - El flujo start.S -> main.c esta funcionando bien
 *
 * Al final entramos en un loop infinito con wfi (Wait For Interrupt)
 * porque un firmware no "termina" como un programa normal, se queda
 * corriendo hasta que apagan el dispositivo.
 * ------------------------------------------------------------------------- */
void main(void)
{
    uart_puts("=================================\n");
    uart_puts("  RISC-V Root of Trust Firmware\n");
    uart_puts("  Booting in M-mode...\n");
    uart_puts("=================================\n");
    uart_puts("[OK] UART initialized\n");
    uart_puts("[OK] Firmware running on QEMU virt (rv64)\n");
    uart_puts("\nHello from bare-metal RISC-V!\n");

    /* Loop infinito, el firmware se queda aca esperando */
    while (1) {
        asm volatile("wfi");
    }
}
