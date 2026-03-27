# ==========================================================================
# Dockerfile - Reproducible build environment for the RoT firmware
# ==========================================================================
#
# This container has everything needed to build and run the project:
#   - RISC-V cross-compiler (gcc)
#   - Python 3 for the attestation tools
#   - Our custom QEMU with the Secure Storage MMIO device
#
# Usage:
#   docker build -t riscv-rot .
#   docker run --rm -it riscv-rot                    # build and run firmware
#   docker run --rm -it riscv-rot make clean         # just clean
#   docker run --rm -it riscv-rot python3 tools/verify_quote.py --demo
#
# Author: Sebastian Alba
# Project: Root of Trust Firmware for RISC-V with PMP isolation
# ==========================================================================

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# install build tools, Python, and QEMU build dependencies
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

# clone and build our custom QEMU with Secure Storage device
RUN git clone --depth 1 https://gitlab.com/secce/qemu-ccore.git /root/qemu-ccore && \
    cd /root/qemu-ccore && \
    ./configure --target-list=riscv64-softmmu --prefix=/opt/qemu-ccore && \
    cd build && ninja -j$(nproc)

# copy firmware source into the container
WORKDIR /root/riscv-rot
COPY include/ include/
COPY src/ src/
COPY lib/ lib/
COPY scripts/ scripts/
COPY tools/ tools/
COPY docs/ docs/
COPY Makefile .
COPY README.md .

# default: build and run the firmware
CMD ["sh", "-c", "make clean && make && make run"]
