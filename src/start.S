/* ==========================================================================
 * start.S - Codigo de arranque (bootstrap) del firmware Root of Trust
 * ==========================================================================
 *
 * Por que es necesario este archivo?
 * ----------------------------------
 * Cuando un procesador se enciende, no tiene idea de nada. No sabe donde
 * esta el stack, no sabe que variables existen, no tiene nada listo.
 * Es como encender una computadora vacia. Alguien tiene que hacer el
 * trabajo de preparar todo antes de que el codigo en C pueda correr.
 * Ese alguien es este archivo.
 *
 * Que hace paso a paso?
 * ---------------------
 *   1. Desactiva las interrupciones para que nada moleste mientras
 *      estamos configurando el sistema
 *   2. Configura el stack pointer (sp), que es el registro que le dice
 *      al procesador donde guardar datos temporales. Sin esto, ninguna
 *      funcion en C puede funcionar
 *   3. Limpia la seccion BSS. Esta es la zona de memoria donde van las
 *      variables globales que no tienen un valor inicial. El estandar de C
 *      dice que tienen que empezar en cero, asi que las llenamos con ceros
 *   4. Salta a la funcion main() que esta escrita en C
 *   5. Si main() retorna por alguna razon (no deberia en un firmware),
 *      el procesador se queda en un loop infinito sin hacer nada
 *
 * En que contexto corre esto?
 * ---------------------------
 * En Machine mode (M-mode), que es el nivel de privilegio
 * mas alto que existe en RISC-V. Aca tenemos control total sobre el hardware,
 * podemos tocar cualquier registro, cualquier zona de memoria...
 * Mas adelante, este firmware va a usar este poder para configurar la
 * proteccion de memoria (PMP) y despues bajar al codigo de usuario a un
 * nivel de privilegio menor donde ya no pueda tocar los secretos.
 *
 * Autor: Sebastian Alba
 * Proyecto: Firmware Root of Trust para RISC-V con aislamiento PMP
 * ========================================================================== */

/* -------------------------------------------------------------------------
 * .section .text.init
 *
 * Aca se le dice al ensamblador que coloque este codigo en una
 * seccion especial llamada .text.init
 *
 * Por que importa esto? Porque en nuestro linker script (virt.ld),
 * esta seccion esta configurada para ir al inicio de la RAM, en la
 * direccion 0x80000000. Eso garantiza que cuando QEMU enciende el
 * procesador simulado, lo primero que ejecuta es ESTE codigo
 * ------------------------------------------------------------------------- */
.section .text.init

/* -------------------------------------------------------------------------
 * .global _start
 *
 * Hace que el  _start sea visible para el linker. Sin esto,
 * el linker no podria encontrar el punto de entrada del programa.
 * En el linker script usamos ENTRY(_start) que basicamente dice
 * que la ejecucion del programa empieza en _start
 * ------------------------------------------------------------------------- */
.global _start

_start:
    /* -----------------------------------------------------------------
     * csrw mie, zero
     *
     * CSR = Control and Status Register
     *   Son registros especiales del procesador que controlan como se
     *   comporta. No son registros normales como t0 o sp, son aparte.
     *
     * mie = Machine Interrupt Enable
     *   Este CSR en particular controla cuales interrupciones estan
     *   activadas. Si un bit esta en 1, esa interrupcion esta habilitada.
     *
     * zero = Es un registro especial de RISC-V que SIEMPRE vale 0.
     *   No importa que le escribamos, siempre va a leer 0.
     *
     * Entonces lo que hacemos es escribir 0 en mie, lo que desactiva
     * todas las interrupciones. Esto es importante porque durante el
     * arranque no queremos que nada nos interrumpa mientras configuramos
     * el stack y limpiamos la memoria.
     * ----------------------------------------------------------------- */
    csrw mie, zero

    /* -----------------------------------------------------------------
     * la sp, __stack_top
     *
     * la = Load Address
     *   Es una pseudo-instruccion (el ensamblador la convierte en
     *   instrucciones reales). Carga una direccion de memoria en
     *   un registro.
     *
     * sp = Stack Pointer
     *   Es el registro que apunta al tope de la pila (stack).
     *
     * __stack_top = Simbolo definido en el linker script (virt.ld)
     *   Apunta a la direccion mas alta de la zona que reservamos
     *   para el stack.
     *
     * Por que necesitamos el stack?
     *   Cada vez que una funcion en C se ejecuta, necesita un lugar
     *   para guardar sus variables locales, los parametros que recibe,
     *   y la direccion a la que tiene que volver cuando termine.
     *   Ese lugar es el stack.
     *
     * En RISC-V el stack crece para abajo (de direcciones altas a
     * bajas), por eso lo inicializamos en el tope.
     * ----------------------------------------------------------------- */
    la sp, __stack_top

    /* -----------------------------------------------------------------
     * Limpieza de la seccion BSS
     *
     * BSS = Block Started by Symbol 
     *
     * Que hay en el BSS?
     *   Todas las variables globales que se declaro sin
     *   darles un valor inicial. Por ejemplo:
     *     int contador;        <-- va al BSS (no tiene valor)
     *     int total = 100;     <-- NO va al BSS (tiene valor, va a .data)
     *
     * El estandar de C garantiza que estas variables empiezan en 0.
     * Pero en bare-metal nadie nos da esa garantia, la memoria RAM
     * puede tener basura. Entonces nosotros mismos recorremos toda
     * la zona BSS escribiendo ceros.
     *
     * __bss_start y __bss_end son simbolos que el linker script define
     * automaticamente para marcar donde empieza y termina el BSS.
     * ----------------------------------------------------------------- */
    la t0, __bss_start       /* t0 = direccion donde empieza el BSS */
    la t1, __bss_end         /* t1 = direccion donde termina el BSS */

bss_clear:
    /* Si t0 ya llego a t1 (o se paso), terminamos de limpiar */
    bge t0, t1, bss_done

    /* sd = Store Doubleword: guarda 8 bytes (64 bits) de ceros
       en la direccion que apunta t0. Usamos 8 bytes porque estamos
       en un procesador de 64 bits */
    sd zero, 0(t0)

    /* Avanzamos el puntero 8 bytes para limpiar el siguiente pedazo */
    addi t0, t0, 8

    /* Volvemos al inicio del ciclo */
    j bss_clear

bss_done:
    /* -----------------------------------------------------------------
     * jal main
     *
     * jal = Jump And Link
     *   Hace dos cosas a la vez:
     *   1. Guarda la direccion de la siguiente instruccion (hang) en
     *      el registro ra (return address)
     *   2. Salta a la funcion main()
     *
     *   Cuando main() ejecute ret (return), el procesador lee ra y
     *   vuelve aca, a la instruccion hang que esta justo abajo
     *
     * A partir de aca el control pasa a codigo C (main.c)
     * ----------------------------------------------------------------- */
    jal main

    /* -----------------------------------------------------------------
     * hang: loop infinito de seguridad
     *
     * Si por alguna razon main() retorna (que se supone q ningun firmware
     *  deberia pasar), nos quedamos aca atrapados.
     *
     * wfi = Wait For Interrupt
     *   Le dice al procesador "no hay nada que hacer, pongase en bajo
     *   consumo hasta que llegue una interrupcion"
     *
     * Pero como desactivamos las interrupciones al inicio con
     * csrw mie, zero... nunca va a llegar ninguna interrupcion
     * y el procesador se queda dormido para siempre.
     *
     * El j hang es por si acaso algun evento espureo despierta al
     * procesador, que vuelva a ejecutar wfi
     * ----------------------------------------------------------------- */
hang:
    wfi
    j hang
