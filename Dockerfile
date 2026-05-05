# Dockerfile - Reproducible build environment for the RoT firmware
#
# Builds a container with the RISC-V cross-compiler and our custom
# QEMU fork. No submodules needed, just clone and build.
#
# Usage:
#   docker build -t riscv-rot .
#   docker run --rm -it riscv-rot
#   docker run --rm -it riscv-rot python3 tools/verify_quote.py --demo

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

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

# build custom QEMU with Secure Storage device (no submodules needed)
RUN git clone --depth 1 https://gitlab.com/secce/qemu-ccore.git /root/qemu-ccore && \
    cd /root/qemu-ccore && \
    ./configure --target-list=riscv64-softmmu && \
    cd build && ninja -j$(nproc)

WORKDIR /root/riscv-rot
COPY include/ include/
COPY src/ src/
COPY lib/ lib/
COPY scripts/ scripts/
COPY tools/ tools/
COPY docs/ docs/
COPY Makefile .
COPY README.md .

CMD ["sh", "-c", "make clean && make && make run"]
