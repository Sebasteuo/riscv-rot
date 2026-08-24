/* ==========================================================================
 * virt.ld - Linker script for the QEMU virt machine (RISC-V 64-bit)
 * ==========================================================================
 *
 * Memory is split into separate regions so PMP can enforce isolation:
 *
 *   0x80000000  M-mode code (.text) + M-mode rodata/data/bss/stack
 *               Only the crypto core runs here. U-mode has no access.
 *   0x80080000  Shared code (uart, sha256, hmac) + its rodata
 *               Both M-mode and U-mode execute these (read+execute).
 *   0x80090000  U-mode code (user, tpm2_api) + rodata/data/bss + U stack
 *               U-mode runs here (read+write+execute on its own memory).
 *   0x80100000  .secret_data (seeds, password) + .secret (PCR, auth state)
 *               Protected by PMP region 0, no U-mode access.
 *
 * The placement is by object file: the linker assigns each .o's sections
 * to the matching region. Sections listed first (shared, U-mode) are
 * consumed before the catch-all M-mode .text grabs the rest.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY
{
    RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 128M
}

SECTIONS
{
    /* ---- Shared code region (R+X for both M and U) at 0x80080000 ---- */
    .text.shared 0x80080000 : {
        __shared_start = .;
        build/uart.o(.text .text.*)
        build/sha256.o(.text .text.*)
        build/hmac.o(.text .text.*)
        build/uart.o(.rodata .rodata.*)
        build/sha256.o(.rodata .rodata.*)
        build/hmac.o(.rodata .rodata.*)
        . = ALIGN(8);
        __shared_end = .;
    } > RAM

    /* ---- U-mode region (R+W+X, U-mode owns it) at 0x80090000 ---- */
    .text.umode 0x80090000 : {
        __umode_start = .;
        build/user.o(.text .text.*)
        build/tpm2_api.o(.text .text.*)
        build/client_app.o(.text .text.*)
        build/user.o(.rodata .rodata.*)
        build/tpm2_api.o(.rodata .rodata.*)
        build/client_app.o(.rodata .rodata.*)
        build/user.o(.data .data.*)
        build/tpm2_api.o(.data .data.*)
        build/client_app.o(.data .data.*)
        . = ALIGN(8);
        __umode_data_end = .;
    } > RAM

    .umode_bss (NOLOAD) : {
        __umode_bss_start = .;
        build/user.o(.bss .bss.* COMMON)
        build/tpm2_api.o(.bss .bss.* COMMON)
        build/client_app.o(.bss .bss.* COMMON)
        *(.umode_bss)
        . = ALIGN(8);
        __umode_bss_end = .;
        __umode_end = .;
    } > RAM

    /* ---- M-mode code at 0x80000000 (catch-all for remaining .text) ---- */
    .text 0x80000000 : {
        __text_start = .;
        *(.text.init)
        *(.text .text.*)
        __text_end = .;
    } > RAM

    .rodata : {
        __rodata_start = .;
        *(.rodata .rodata.*)
        __rodata_end = .;
    } > RAM

    .data : {
        *(.data .data.*)
    } > RAM

    .got : {
        *(.got*)
    } > RAM

    .bss : {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } > RAM

    .stack (NOLOAD) : {
        . = . + 0x10000;
        __stack_top = .;
    } > RAM

    /* ---- Protected secrets at 0x80100000 (PMP region 0, no U access) ---- */
    .secret_data 0x80100000 : {
        . = ALIGN(8);
        __secret_data_start = .;
        *(.secret_data)
        . = ALIGN(8);
        __secret_data_end = .;
    } > RAM

    .secret (NOLOAD) : {
        . = ALIGN(8);
        __secret_start = .;
        *(.secret)
        . = ALIGN(8);
        __secret_end = .;
    } > RAM

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
