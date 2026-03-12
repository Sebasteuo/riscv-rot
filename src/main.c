/* ==========================================================================

 * main.c - Punto de entrada principal del firmware Root of Trust

 * ==========================================================================

 *

 * Aca arranca toda la logica del firmware despues de que start.S

 * prepara el stack y limpia el BSS.

 *

 * En la Fase 1 esto solo imprimia un mensaje para confirmar que el

 * arranque funcionaba. Ahora en la Fase 2 vamos a agregar la

 * configuracion de PMP para proteger zonas de memoria.

 *

 * Por ahora el main sigue siendo simple, imprime el banner y confirma

 * que estamos corriendo en M-mode. En los proximos pasos vamos a ir

 * agregando la logica de PMP, el salto a U-mode y el manejo de traps.

 *

 * Autor: Sebastian Alba

 * Proyecto: Firmware Root of Trust para RISC-V con aislamiento PMP

 * ========================================================================== */

#include <stdint.h>

#include "uart.h"

/* -------------------------------------------------------------------------

 * main - Funcion principal del firmware

 *

 * Lo que hace por ahora:

 *   1. Imprime el banner del firmware

 *   2. Confirma que el UART funciona

 *   3. Se queda en un loop infinito esperando

 *

 * En los siguientes pasos de la Fase 2, aca vamos a:

 *   - Configurar las regiones PMP

 *   - Instalar el trap handler

 *   - Saltar a U-mode

 *   - Probar que PMP bloquea accesos no autorizados

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

