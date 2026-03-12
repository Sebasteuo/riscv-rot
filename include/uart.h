/* ==========================================================================
 * uart.h - Funciones para imprimir por el puerto serial
 * ==========================================================================
 *
 * Como en bare-metal no tenemos printf ni nada parecido (no hay sistema
 * operativo que nos de esas funciones), nos toca escribir nosotros mismos
 * las funciones para mandar texto al puerto serial (UART).
 *
 * La idea es simple: el UART esta mapeado en una direccion de memoria
 * fija (0x10000000 en la maquina virt de QEMU). Si escribimos un byte
 * ahi, QEMU lo muestra como un caracter en la terminal. Con eso nos
 * alcanza para imprimir mensajes de debug y ver que esta pasando.
 *
 * Autor: Sebastian Alba
 * Proyecto: Firmware Root of Trust para RISC-V con aislamiento PMP
 * ========================================================================== */

#ifndef UART_H
#define UART_H

#include <stdint.h>

/*
 * Direccion del UART0 en la maquina virt de QEMU.
 * No es un numero random, viene de como QEMU define su mapa de memoria.
 */
#define UART0_BASE 0x10000000

/* Manda un solo caracter al UART */
void uart_putc(char c);

/* Manda un string completo al UART, caracter por caracter */
void uart_puts(const char *s);

/*
 * Imprime un numero en formato hexadecimal.
 * Esto es muy util para debug, por ejemplo para mostrar direcciones
 * de memoria o valores de registros y poder verificar que estan bien
 */
void uart_put_hex(uint64_t value);

#endif /* UART_H */
