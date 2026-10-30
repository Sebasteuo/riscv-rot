/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */
/* ==========================================================================
 * secure_storage.h - Secure Storage abstraction layer
 * ==========================================================================
 *
 * Interface for storing and retrieving keys and sensitive data.
 * The rest of the firmware calls ss_write_key() and ss_read_key()
 * without worrying about how the data is stored underneath.
 *
 * The backend talks to the Secure Storage MMIO device that we added
 * to QEMU at address 0x10200000. The device has a set of registers
 * that we write to in a specific sequence to store and retrieve data.
 *
 * Only M-mode code should call these functions. PMP protects the
 * device address so U-mode cannot touch it.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#ifndef SECURE_STORAGE_H
#define SECURE_STORAGE_H

#include <stdint.h>

/* -------------------------------------------------------------------------
 * MMIO device base address and register offsets
 *
 * These match exactly what we defined in the QEMU device
 * (hw/misc/secure_storage.c in qemu-ccore). The device sits at
 * 0x10200000 and has 6 registers of 32 bits each.
 * ------------------------------------------------------------------------- */
#define SS_MMIO_BASE    0x10200000UL

#define SS_REG_CMD      0x00    /* write a command to execute it */
#define SS_REG_STATUS   0x04    /* result of the last operation */
#define SS_REG_SLOT_ID  0x08    /* which slot to use (0-7) */
#define SS_REG_OFFSET   0x0C    /* byte offset within the slot */
#define SS_REG_SIZE     0x10    /* number of bytes for the operation */
#define SS_REG_DATA     0x14    /* data goes in/out here, 4 bytes at a time */

/* commands we can write to REG_CMD */
#define SS_CMD_WRITE    0x01
#define SS_CMD_READ     0x02
#define SS_CMD_ERASE    0x03
#define SS_CMD_CHECK    0x04

/* status codes we read from REG_STATUS */
#define SS_STATUS_OK        0x00
#define SS_STATUS_ERROR     0x01
#define SS_STATUS_EMPTY     0x02
#define SS_STATUS_HAS_DATA  0x03

/* storage dimensions (must match the QEMU device) */
#define SS_NUM_SLOTS     8
#define SS_MAX_KEY_SIZE  64

/* -------------------------------------------------------------------------
 * Key IDs
 * Each key gets a unique ID that maps to a slot in the device.
 * ------------------------------------------------------------------------- */
typedef enum {
    KEY_ID_EK   = 0,
    KEY_ID_SRK  = 1,
    KEY_ID_PCR0 = 2,
    KEY_ID_PCR1 = 3,
    KEY_ID_PCR2 = 4,
    KEY_ID_MAX  = 8
} key_id_t;

/* -------------------------------------------------------------------------
 * Public API (same as before, backend changed to MMIO)
 * ------------------------------------------------------------------------- */
void ss_init(void);
int ss_write_key(key_id_t id, const uint8_t *data, uint32_t size);
int ss_read_key(key_id_t id, uint8_t *data, uint32_t *size);
int ss_key_exists(key_id_t id);
int ss_delete_key(key_id_t id);
void ss_dump(void);

#endif /* SECURE_STORAGE_H */
