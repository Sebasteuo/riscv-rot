# ==========================================================================
# Makefile - Automatizacion de compilacion del firmware Root of Trust
# ==========================================================================
#
# 
# Comandos disponibles:
#   make        -> Compila el firmware y genera firmware.elf
#   make run    -> Compila y ejecuta en QEMU
#   make clean  -> Borra los archivos generados
#
# Autor: Sebastian Alba
# Proyecto: Firmware Root of Trust para RISC-V con aislamiento PMP
# ==========================================================================

# --------------------------------------------------------------------------
# Prefijo del toolchain de cross-compilacion
# Como estamos compilando en una maquina ARM (o x86) pero el codigo
# tiene que correr en RISC-V, usamos un compilador cruzado.
# Todos los comandos del toolchain empiezan con este prefijo.
# --------------------------------------------------------------------------
CROSS = riscv64-linux-gnu-

# --------------------------------------------------------------------------
# Herramientas del toolchain
# CC      = El compilador de C (gcc)
# OBJCOPY = Herramienta para convertir formatos de archivo
# OBJDUMP = Herramienta para desensamblar (ver el codigo de maquina)
# --------------------------------------------------------------------------
CC = $(CROSS)gcc
OBJCOPY = $(CROSS)objcopy
OBJDUMP = $(CROSS)objdump

# --------------------------------------------------------------------------
# Flags de compilacion (CFLAGS)
#
# -march=rv64g      Arquitectura RISC-V 64 bits con extensiones generales
#                    (g = imafd: enteros, multiplicacion, atomicas, float, double)
# -mabi=lp64d       ABI con long y punteros de 64 bits, doubles en hardware
# -nostdlib          No usar la biblioteca estandar de C (no hay OS)
# -nostartfiles      No usar los archivos de inicio estandar (nosotros tenemos start.S)
# -ffreestanding     Modo freestanding: no asumir que existe un OS
# -g                 Incluir informacion de debug (util para depurar)
# -O0                Sin optimizaciones (para que el codigo sea predecible al depurar)
# -static            Generar un ejecutable estatico (sin dependencias dinamicas)
# -mcmodel=medany    Modelo de codigo que permite acceder a cualquier direccion
#                    Necesario porque nuestro codigo vive en 0x80000000
# --------------------------------------------------------------------------
CFLAGS = -march=rv64g -mabi=lp64d -nostdlib -nostartfiles -ffreestanding -g -O0 -static -mcmodel=medany

# --------------------------------------------------------------------------
# Flags del linker (LDFLAGS)
#
# -T scripts/virt.ld       Usar nuestro linker script personalizado
# -nostdlib                 No linkear con la biblioteca estandar
# -static                   Linkeo estatico
# --no-dynamic-linker       No incluir referencia a linker dinamico
# --------------------------------------------------------------------------
LDFLAGS = -T scripts/virt.ld -nostdlib -static -Wl,--no-dynamic-linker

# --------------------------------------------------------------------------
# Archivos fuente y nombre del ejecutable final
# --------------------------------------------------------------------------
SRCS_C = src/main.c
SRCS_S = src/start.S
TARGET = firmware

# --------------------------------------------------------------------------
# Regla principal: compilar el firmware
# Genera firmware.elf (el ejecutable) y firmware.dump (el desensamblado,
# que es util para verificar que el codigo quedo donde esperamos)
# --------------------------------------------------------------------------
all: $(TARGET).elf

$(TARGET).elf: $(SRCS_S) $(SRCS_C)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS_S) $(SRCS_C)
	$(OBJDUMP) -d $@ > $(TARGET).dump

# --------------------------------------------------------------------------
# Regla de limpieza: borra los archivos generados
# --------------------------------------------------------------------------
clean:
	rm -f $(TARGET).elf $(TARGET).dump

# --------------------------------------------------------------------------
# Regla para ejecutar: compila y lanza QEMU
#
# -machine virt     Maquina virtual generica de RISC-V
# -cpu rv64         Procesador RISC-V de 64 bits
# -m 128M           128 MB de RAM
# -nographic        Sin ventana grafica, todo por terminal
# -bios none        No cargar ningun BIOS, saltar directo a nuestro codigo
# -kernel           Cargar nuestro ELF como si fuera el kernel
# -smp 1            Un solo nucleo de procesador
# --------------------------------------------------------------------------
run: $(TARGET).elf
	qemu-system-riscv64 -machine virt -cpu rv64 -m 128M -nographic -bios none -kernel $(TARGET).elf -smp 1

.PHONY: all clean run
