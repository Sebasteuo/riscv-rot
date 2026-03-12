# ==========================================================================
# Dockerfile - Entorno reproducible para el firmware Root of Trust
# ==========================================================================
#
# Este Dockerfile crea un container con todo lo necesario para compilar
# y ejecutar el firmware sin tener que instalar nada manualmente.
# Cualquiera que tenga Docker puede clonar el repo, hacer docker build
# y docker run, y ya tiene todo listo.
#
# Que incluye:
#   - QEMU para simular el procesador RISC-V de 64 bits
#   - Toolchain de cross-compilacion (gcc para RISC-V)
#   - make, git y herramientas basicas
#
# Como usarlo:
#   docker build -t riscv-rot .
#   docker run -it riscv-rot
#   make run
#
# Autor: Sebastian Alba
# Proyecto: Firmware Root of Trust para RISC-V con aislamiento PMP
# ==========================================================================

FROM ubuntu:24.04

# Evitar que apt pregunte cosas durante la instalacion
ENV DEBIAN_FRONTEND=noninteractive

# Instalar todo lo que necesitamos
RUN apt-get update && apt-get install -y \
    qemu-system-misc \
    gcc-riscv64-linux-gnu \
    binutils-riscv64-linux-gnu \
    make \
    git \
    && rm -rf /var/lib/apt/lists/*

# Crear directorio de trabajo
WORKDIR /workspace

# Copiar todo el proyecto al container
COPY . .

# Compilar el firmware al construir la imagen
RUN make clean && make

# Cuando el container arranque, abrir un shell listo para trabajar
CMD ["/bin/bash"]
