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
 *   0x80200000  .secret_data (seeds, password) + .secret (PCR, auth state)
 *               Protected by PMP region 0, no U-mode access.
 *
 * The placement is by object file. The linker assigns each .o's sections
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
        build/attack.o(.text .text.*)
        build/profile.o(.text .text.*)
        build/board.o(.text .text.*)
        build/beebsc.o(.text .text.*)
        build/aha_mont64__mont64.o(.text .text.*)
        build/crc32__crc_32.o(.text .text.*)
        build/depthconv__depthconv.o(.text .text.*)
        build/edn__libedn.o(.text .text.*)
        build/huffbench__libhuffbench.o(.text .text.*)
        build/matmult_int__matmult-int.o(.text .text.*)
        build/md5sum__md5.o(.text .text.*)
        build/nettle_aes__nettle-aes.o(.text .text.*)
        build/nettle_sha256__nettle-sha256.o(.text .text.*)
        build/nsichneu__libnsichneu.o(.text .text.*)
        build/picojpeg__libpicojpeg.o(.text .text.*)
        build/picojpeg__picojpeg_test.o(.text .text.*)
        build/qrduino__qrencode.o(.text .text.*)
        build/qrduino__qrframe.o(.text .text.*)
        build/qrduino__qrtest.o(.text .text.*)
        build/sglib_combined__combined.o(.text .text.*)
        build/slre__libslre.o(.text .text.*)
        build/statemate__libstatemate.o(.text .text.*)
        build/tarfind__tarfind.o(.text .text.*)
        build/ud__libud.o(.text .text.*)
        build/wikisort__libwikisort.o(.text .text.*)
        build/xgboost__testbench.o(.text .text.*)
        build/xgboost__xgboost.o(.text .text.*)
        build/user.o(.rodata .rodata.*)
        build/tpm2_api.o(.rodata .rodata.*)
        build/client_app.o(.rodata .rodata.*)
        build/attack.o(.rodata .rodata.*)
        build/profile.o(.rodata .rodata.*)
        build/board.o(.rodata .rodata.*)
        build/beebsc.o(.rodata .rodata.*)
        build/aha_mont64__mont64.o(.rodata .rodata.*)
        build/crc32__crc_32.o(.rodata .rodata.*)
        build/depthconv__depthconv.o(.rodata .rodata.*)
        build/edn__libedn.o(.rodata .rodata.*)
        build/huffbench__libhuffbench.o(.rodata .rodata.*)
        build/matmult_int__matmult-int.o(.rodata .rodata.*)
        build/md5sum__md5.o(.rodata .rodata.*)
        build/nettle_aes__nettle-aes.o(.rodata .rodata.*)
        build/nettle_sha256__nettle-sha256.o(.rodata .rodata.*)
        build/nsichneu__libnsichneu.o(.rodata .rodata.*)
        build/picojpeg__libpicojpeg.o(.rodata .rodata.*)
        build/picojpeg__picojpeg_test.o(.rodata .rodata.*)
        build/qrduino__qrencode.o(.rodata .rodata.*)
        build/qrduino__qrframe.o(.rodata .rodata.*)
        build/qrduino__qrtest.o(.rodata .rodata.*)
        build/sglib_combined__combined.o(.rodata .rodata.*)
        build/slre__libslre.o(.rodata .rodata.*)
        build/statemate__libstatemate.o(.rodata .rodata.*)
        build/tarfind__tarfind.o(.rodata .rodata.*)
        build/ud__libud.o(.rodata .rodata.*)
        build/wikisort__libwikisort.o(.rodata .rodata.*)
        build/xgboost__testbench.o(.rodata .rodata.*)
        build/xgboost__xgboost.o(.rodata .rodata.*)
        build/user.o(.data .data.*)
        build/tpm2_api.o(.data .data.*)
        build/client_app.o(.data .data.*)
        build/attack.o(.data .data.*)
        build/profile.o(.data .data.*)
        build/board.o(.data .data.*)
        build/beebsc.o(.data .data.*)
        build/aha_mont64__mont64.o(.data .data.*)
        build/crc32__crc_32.o(.data .data.*)
        build/depthconv__depthconv.o(.data .data.*)
        build/edn__libedn.o(.data .data.*)
        build/huffbench__libhuffbench.o(.data .data.*)
        build/matmult_int__matmult-int.o(.data .data.*)
        build/md5sum__md5.o(.data .data.*)
        build/nettle_aes__nettle-aes.o(.data .data.*)
        build/nettle_sha256__nettle-sha256.o(.data .data.*)
        build/nsichneu__libnsichneu.o(.data .data.*)
        build/picojpeg__libpicojpeg.o(.data .data.*)
        build/picojpeg__picojpeg_test.o(.data .data.*)
        build/qrduino__qrencode.o(.data .data.*)
        build/qrduino__qrframe.o(.data .data.*)
        build/qrduino__qrtest.o(.data .data.*)
        build/sglib_combined__combined.o(.data .data.*)
        build/slre__libslre.o(.data .data.*)
        build/statemate__libstatemate.o(.data .data.*)
        build/tarfind__tarfind.o(.data .data.*)
        build/ud__libud.o(.data .data.*)
        build/wikisort__libwikisort.o(.data .data.*)
        build/xgboost__testbench.o(.data .data.*)
        build/xgboost__xgboost.o(.data .data.*)
        . = ALIGN(8);
        __umode_data_end = .;
    } > RAM

    .umode_bss (NOLOAD) : {
        __umode_bss_start = .;
        build/user.o(.bss .bss.* COMMON)
        build/tpm2_api.o(.bss .bss.* COMMON)
        build/client_app.o(.bss .bss.* COMMON)
        build/attack.o(.bss .bss.* COMMON)
        build/profile.o(.bss .bss.* COMMON)
        build/board.o(.bss .bss.* COMMON)
        build/beebsc.o(.bss .bss.* COMMON)
        build/aha_mont64__mont64.o(.bss .bss.* COMMON)
        build/crc32__crc_32.o(.bss .bss.* COMMON)
        build/depthconv__depthconv.o(.bss .bss.* COMMON)
        build/edn__libedn.o(.bss .bss.* COMMON)
        build/huffbench__libhuffbench.o(.bss .bss.* COMMON)
        build/matmult_int__matmult-int.o(.bss .bss.* COMMON)
        build/md5sum__md5.o(.bss .bss.* COMMON)
        build/nettle_aes__nettle-aes.o(.bss .bss.* COMMON)
        build/nettle_sha256__nettle-sha256.o(.bss .bss.* COMMON)
        build/nsichneu__libnsichneu.o(.bss .bss.* COMMON)
        build/picojpeg__libpicojpeg.o(.bss .bss.* COMMON)
        build/picojpeg__picojpeg_test.o(.bss .bss.* COMMON)
        build/qrduino__qrencode.o(.bss .bss.* COMMON)
        build/qrduino__qrframe.o(.bss .bss.* COMMON)
        build/qrduino__qrtest.o(.bss .bss.* COMMON)
        build/sglib_combined__combined.o(.bss .bss.* COMMON)
        build/slre__libslre.o(.bss .bss.* COMMON)
        build/statemate__libstatemate.o(.bss .bss.* COMMON)
        build/tarfind__tarfind.o(.bss .bss.* COMMON)
        build/ud__libud.o(.bss .bss.* COMMON)
        build/wikisort__libwikisort.o(.bss .bss.* COMMON)
        build/xgboost__testbench.o(.bss .bss.* COMMON)
        build/xgboost__xgboost.o(.bss .bss.* COMMON)
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

    /* ---- Protected secrets at 0x80200000 (PMP region 0, no U access) ----
     * Moved up from 0x80100000 when the U-mode region grew to 512 KB
     * with the Embench suite: PMP in NAPOT mode needs power-of-two
     * sizes, and a 512 KB U-mode region starting at 0x80090000 would
     * otherwise reach into the secret zone. */
    .secret_data 0x80200000 : {
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
