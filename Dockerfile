# ==========================================================================
# Dockerfile - Reproducible build environment for the RoT firmware
# ==========================================================================
#
# This container has everything needed to build and run the project:
#   - RISC-V cross-compiler (gcc)
#   - Our custom QEMU with the Secure Storage MMIO device
#
# Usage:
#   docker build -t riscv-rot .
#   docker run --rm riscv-rot              (builds and runs the firmware)
#   docker run --rm riscv-rot make clean   (just clean)
#
# Author: Sebastian Alba
# Project: Root of Trust Firmware for RISC-V with PMP isolation
# ==========================================================================

FROM ubuntu:24.04

# avoid interactive prompts during apt install
ENV DEBIAN_FRONTEND=noninteractive

# install build tools and QEMU build dependencies
RUN apt-get update && apt-get install -y \
    gcc-riscv64-linux-gnu \
    binutils-riscv64-linux-gnu \
    make \
    git \
    ninja-build \
    libglib2.0-dev \
    libpixman-1-dev \
    libslirp-dev \
    python3 \
    python3-venv \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# copy our firmware source
WORKDIR /root/riscv-rot
COPY include/ include/
COPY src/ src/
COPY lib/ lib/
COPY scripts/ scripts/
COPY Makefile .

# clone and build our custom QEMU with Secure Storage device
# We clone from GitLab SECCE group
RUN git clone --depth 1 https://gitlab.com/secce/qemu-ccore.git /root/qemu-ccore && \
    cd /root/qemu-ccore && \
    ./configure --target-list=riscv64-softmmu --prefix=/opt/qemu-ccore && \
    cd build && ninja -j$(nproc) && \
    cd /root/riscv-rot

# default: build firmware and run it
CMD ["sh", "-c", "make clean && make && make run"]
