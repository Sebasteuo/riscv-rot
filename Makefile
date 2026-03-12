# ==========================================================================
# Makefile - Automatizacion de compilacion del firmware Root of Trust
# ==========================================================================
#
# En vez de escribir comandos largos cada vez que queremos compilar,
# solo escribimos "make" y este archivo se encarga de todo.
#
# Comandos disponibles
#   make        compila el firmware y genera firmware.elf
#   make run    compila y ejecuta en QEMU
#   make clean  borra los archivos generados
#
# Autor: Sebastian Alba
# Proyecto: Firmware Root of Trust para RISC-V con aislamiento PMP
# ==========================================================================

# Prefijo del toolchain de cross-compilacion
# Nosotros compilamos en ARM pero el codigo tiene que correr en RISC-V,
# por eso usamos un compilador cruzado que genera codigo para otra arquitectura
CROSS = riscv64-linux-gnu-
CC = $(CROSS)gcc
OBJCOPY = $(CROSS)objcopy
OBJDUMP = $(CROSS)objdump

# Flags de compilacion
# -march=rv64g       le decimos que compile para RISC-V 64 bits con extensiones generales
# -mabi=lp64d        ABI con long y punteros de 64 bits
# -nostdlib           que no use la biblioteca estandar porque no hay OS
# -nostartfiles       que no use archivos de inicio estandar, nosotros tenemos start.S
# -ffreestanding      modo freestanding, que no asuma que hay un OS debajo
# -g                  incluir info de debug para poder depurar
# -O0                 sin optimizaciones, asi el codigo es predecible al depurar
# -static             todo estatico, sin dependencias dinamicas
# -mcmodel=medany     permite acceder a direcciones altas como 0x80000000
# -Iinclude           que busque los headers en la carpeta include/
CFLAGS = -march=rv64g -mabi=lp64d -nostdlib -nostartfiles -ffreestanding -g -O0 -static -mcmodel=medany -Iinclude

# Flags del linker
LDFLAGS = -T scripts/virt.ld -nostdlib -static -Wl,--no-dynamic-linker

# Archivos fuente
SRCS_C = src/main.c src/uart.c
SRCS_S = src/start.S
TARGET = firmware

# Regla principal, compila el firmware
all: $(TARGET).elf

$(TARGET).elf: $(SRCS_S) $(SRCS_C)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS_S) $(SRCS_C)
	$(OBJDUMP) -d $@ > $(TARGET).dump

# Borra los archivos generados para empezar limpio
clean:
	rm -f $(TARGET).elf $(TARGET).dump

# Compila y lanza QEMU con nuestro firmware
# -machine virt    maquina virtual generica de RISC-V
# -cpu rv64        procesador de 64 bits
# -m 128M          le damos 128 MB de RAM
# -nographic       sin ventana grafica, todo sale por la terminal
# -bios none       que no cargue ningun BIOS, que salte directo a nuestro codigo
# -kernel          le pasamos nuestro ELF como si fuera el kernel
# -smp 1           un solo nucleo de procesador
run: $(TARGET).elf
	qemu-system-riscv64 -machine virt -cpu rv64 -m 128M -nographic -bios none -kernel $(TARGET).elf -smp 1

.PHONY: all clean run
