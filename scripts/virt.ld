/* ==========================================================================
 * virt.ld - Linker script para la maquina virt de QEMU (RISC-V 64 bits)
 * ==========================================================================
 *
 * Que es un linker script?
 * ------------------------
 * Cuando compilamos codigo en C o ensamblador, el compilador genera
 * archivos objeto (.o) con el codigo de maquina. Pero esos archivos
 * todavia no saben EN QUE DIRECCION de memoria van a vivir.
 *
 * El linker script es el archivo que le dice al linker (la herramienta
 * que junta todo) exactamente donde poner cada pedazo del programa
 * en la memoria. Esto es critico en bare-metal porque no hay sistema
 * operativo que se encargue de cargar el programa en memoria.
 *
 * Por que la direccion 0x80000000?
 * --------------------------------
 * En la maquina "virt" de QEMU para RISC-V, la memoria RAM empieza
 * en la direccion 0x80000000. Esto no es algo que decidimos nosotros,
 * viene definido por el hardware (o en este caso, por la especificacion
 * de la maquina virtual). Cuando QEMU arranca con -bios none -kernel,
 * salta directamente a 0x80000000, asi que nuestro codigo tiene que
 * estar ahi.
 *
 * Que secciones tiene un programa?
 * --------------------------------
 *   .text     = El codigo ejecutable (las instrucciones del procesador)
 *   .rodata   = Datos de solo lectura (constantes, strings)
 *   .data     = Variables globales inicializadas (ej: int x = 5)
 *   .bss      = Variables globales sin inicializar (ej: int x;)
 *   .stack    = Espacio reservado para el stack
 *   .got      = Global Offset Table, tabla que usa el compilador
 *               para resolver direcciones de simbolos
 *
 * Al final descartamos secciones que no necesitamos en bare-metal
 * como .dynamic, .interp, etc. Esas son para ejecutables que corren
 * sobre un sistema operativo con linker dinamico.
 *
 * Autor: Sebastian Alba
 * Proyecto: Firmware Root of Trust para RISC-V con aislamiento PMP
 * ========================================================================== */

OUTPUT_ARCH(riscv)
ENTRY(_start)

/*
 * Definimos la memoria disponible.
 * ORIGIN = donde empieza la RAM
 * LENGTH = cuanta RAM tenemos (128 MB es lo que le pasamos a QEMU con -m 128M)
 * rwx = esta memoria permite lectura, escritura y ejecucion
 */
MEMORY
{
    RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 128M
}

SECTIONS
{
    /* Forzamos que todo empiece en 0x80000000 */
    . = 0x80000000;

    /*
     * Seccion .text - Codigo ejecutable
     * .text.init va primero porque ahi esta _start (el punto de entrada)
     * Despues va el resto del codigo (.text*)
     */
    .text : {
        *(.text.init)
        *(.text*)
    } > RAM

    /*
     * Seccion .rodata - Datos de solo lectura
     * Aca van los strings como "Hello from bare-metal RISC-V!"
     * y cualquier constante que definamos
     */
    .rodata : {
        *(.rodata*)
    } > RAM

    /*
     * Seccion .data - Variables globales inicializadas
     * Por ahora no tenemos ninguna, pero cuando empecemos
     * a guardar configuraciones van a ir aca
     */
    .data : {
        *(.data*)
    } > RAM

    /*
     * Seccion .got - Global Offset Table
     * El compilador la usa internamente para resolver direcciones
     * cuando usamos -mcmodel=medany. Necesitamos incluirla para
     * que el linker no se queje
     */
    .got : {
        *(.got*)
    } > RAM

    /*
     * Seccion .bss - Variables globales sin inicializar
     * __bss_start y __bss_end son simbolos que start.S usa para
     * saber que zona de memoria tiene que llenar con ceros
     */
    .bss : {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        __bss_end = .;
    } > RAM

    /*
     * Seccion .stack - Espacio para el stack
     * NOLOAD significa que no ocupa espacio en el archivo ELF,
     * solo reserva espacio en memoria
     * 0x10000 = 64 KB de stack, mas que suficiente para nuestro firmware
     * __stack_top queda apuntando al tope, que es donde start.S
     * inicializa el stack pointer
     */
    .stack (NOLOAD) : {
        . = . + 0x10000;
        __stack_top = .;
    } > RAM

    /*
     * Secciones que descartamos
     * Estas secciones son para ejecutables que corren sobre un OS
     * con linker dinamico. En bare-metal no las necesitamos para nada
     */
    /DISCARD/ : {
        *(.eh_frame*)
        *(.note*)
        *(.comment)
        *(.riscv.attributes)
        *(.interp)
        *(.dynamic)
        *(.dynsym)
        *(.dynstr)
        *(.gnu.hash)
        *(.rela*)
    }
}
