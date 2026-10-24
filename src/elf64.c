#include "elf64.h"

/*
 * Stage-1 ELF loader.
 *
 * Runs only after the image signature has been verified, so the data
 * is authenticated. Fields are still validated before use, because an
 * authenticated image can still be malformed, and a loader that trusts
 * its input is exactly the failure mode BootStomp documents.
 */

static void copy_bytes(uint8_t *dst, const uint8_t *src, uint64_t n)
{
    uint64_t i;

    for (i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

static void zero_bytes(uint8_t *dst, uint64_t n)
{
    uint64_t i;

    for (i = 0; i < n; i++) {
        dst[i] = 0;
    }
}

static elf_result_t check_header(const elf64_ehdr_t *eh, uint32_t image_size)
{
    uint64_t ph_end;

    if (eh->e_ident[0] != ELFMAG0 || eh->e_ident[1] != ELFMAG1 ||
        eh->e_ident[2] != ELFMAG2 || eh->e_ident[3] != ELFMAG3) {
        return ELF_ERR_MAGIC;
    }
    if (eh->e_ident[4] != ELFCLASS64) {
        return ELF_ERR_CLASS;
    }
    if (eh->e_type != ET_EXEC) {
        return ELF_ERR_TYPE;
    }
    if (eh->e_machine != EM_RISCV) {
        return ELF_ERR_MACHINE;
    }
    if (eh->e_phnum == 0 || eh->e_phnum > ELF_MAX_PHNUM) {
        return ELF_ERR_PHNUM;
    }
    if (eh->e_phentsize != sizeof(elf64_phdr_t)) {
        return ELF_ERR_PHOFF;
    }

    /* The program header table must lie inside the image */
    ph_end = eh->e_phoff + (uint64_t)eh->e_phnum * eh->e_phentsize;
    if (eh->e_phoff >= image_size || ph_end > (uint64_t)image_size) {
        return ELF_ERR_PHOFF;
    }

    return ELF_OK;
}

static elf_result_t check_segment(const elf64_phdr_t *ph, uint32_t image_size)
{
    uint64_t file_end;
    uint64_t mem_end;

    /* memsz below filesz would mean copying past the destination */
    if (ph->p_memsz < ph->p_filesz) {
        return ELF_ERR_SEGMENT_SIZE;
    }

    /* Source range must lie inside the image */
    file_end = ph->p_offset + ph->p_filesz;
    if (file_end < ph->p_offset || file_end > (uint64_t)image_size) {
        return ELF_ERR_SEGMENT_SIZE;
    }

    /* Destination range must lie inside the region the loader may write */
    mem_end = ph->p_paddr + ph->p_memsz;
    if (mem_end < ph->p_paddr ||
        ph->p_paddr < ELF_LOAD_MIN_ADDR ||
        mem_end > ELF_LOAD_MAX_ADDR) {
        return ELF_ERR_SEGMENT_RANGE;
    }

    return ELF_OK;
}

elf_result_t elf_load(const uint8_t *image, uint32_t image_size,
                      uint64_t *entry)
{
    const elf64_ehdr_t *eh = (const elf64_ehdr_t *)image;
    const elf64_phdr_t *ph;
    elf_result_t rc;
    uint16_t i;

    if (image_size < sizeof(elf64_ehdr_t)) {
        return ELF_ERR_MAGIC;
    }

    rc = check_header(eh, image_size);
    if (rc != ELF_OK) {
        return rc;
    }

    /* Validate every segment before writing anything */
    for (i = 0; i < eh->e_phnum; i++) {
        ph = (const elf64_phdr_t *)(image + eh->e_phoff +
                                    (uint64_t)i * eh->e_phentsize);
        if (ph->p_type != PT_LOAD) {
            continue;
        }
        rc = check_segment(ph, image_size);
        if (rc != ELF_OK) {
            return rc;
        }
    }

    /* Only now place the segments */
    for (i = 0; i < eh->e_phnum; i++) {
        ph = (const elf64_phdr_t *)(image + eh->e_phoff +
                                    (uint64_t)i * eh->e_phentsize);
        if (ph->p_type != PT_LOAD) {
            continue;
        }
        copy_bytes((uint8_t *)ph->p_paddr, image + ph->p_offset,
                   ph->p_filesz);
        /* The part of memsz beyond filesz is bss and must be cleared */
        zero_bytes((uint8_t *)(ph->p_paddr + ph->p_filesz),
                   ph->p_memsz - ph->p_filesz);
    }

    *entry = eh->e_entry;
    return ELF_OK;
}
