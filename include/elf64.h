/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */
#ifndef ELF64_H
#define ELF64_H

#include <stdint.h>

/*
 * Minimal ELF64 definitions for the Stage-1 loader.
 *
 * Only what is needed to walk the program headers and copy PT_LOAD
 * segments to their physical addresses. Stage-2 is statically linked,
 * so there is no relocation or symbol resolution to do.
 *
 * This parser only ever runs on data whose signature has already been
 * verified. Header fields are still range checked before use, as
 * defence in depth: BootStomp (USENIX Security 2017) found that real
 * secure boot failures come from parsing logic rather than from the
 * cryptography.
 */

#define EI_NIDENT   16
#define ELFMAG0     0x7F
#define ELFMAG1     'E'
#define ELFMAG2     'L'
#define ELFMAG3     'F'
#define ELFCLASS64  2
#define ET_EXEC     2
#define EM_RISCV    243
#define PT_LOAD     1

typedef struct {
    uint8_t  e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf64_ehdr_t;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} elf64_phdr_t;

/* Segment permission bits, from the ELF specification */
#define PF_X  0x1
#define PF_W  0x2
#define PF_R  0x4

/* Bounds the loader accepts for segment placement.
 *
 * The top has to stay below the Stage-1 code at 0x80400000 and the
 * Stage-1 stack at 0x80500000, and below the signed image at 0x84000000.
 * If the window reached any of those, a segment could overwrite the
 * loader while it runs, or the header that the copy loop keeps
 * re-reading.
 *
 * Stage-2 reaches 0x802001b0 today, so this leaves about 1 MB of room. A
 * firmware that outgrows the window is rejected with
 * ELF_ERR_SEGMENT_RANGE, which fails loudly instead of corrupting
 * memory.
 */
#define ELF_LOAD_MIN_ADDR   0x80000000UL
#define ELF_LOAD_MAX_ADDR   0x80300000UL
#define ELF_MAX_PHNUM       16

typedef enum {
    ELF_OK = 0,
    ELF_ERR_MAGIC,
    ELF_ERR_CLASS,
    ELF_ERR_TYPE,
    ELF_ERR_MACHINE,
    ELF_ERR_PHNUM,
    ELF_ERR_PHOFF,
    ELF_ERR_SEGMENT_RANGE,
    ELF_ERR_SEGMENT_SIZE,
    ELF_ERR_ENTRY,
} elf_result_t;

elf_result_t elf_load(const uint8_t *image, uint32_t image_size,
                      uint64_t *entry);

#endif /* ELF64_H */
