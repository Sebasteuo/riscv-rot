/* ==========================================================================
 * secure_storage.c - Secure Storage implementation (MMIO backend)
 * ==========================================================================
 *
 * This talks to the Secure Storage MMIO device we added to QEMU.
 * The device lives at 0x10200000 and has a set of 32-bit registers
 * that we read/write in a specific sequence to store and retrieve data.
 *
 * The basic flow for writing a key:
 *   1. Set SLOT_ID to the slot we want
 *   2. Set OFFSET to 0 (start from the beginning)
 *   3. Write CMD_WRITE to CMD (tells the device to get ready)
 *   4. Write the data 4 bytes at a time to the DATA register
 *
 * For reading its the reverse:
 *   1. Set SLOT_ID
 *   2. Set OFFSET to 0
 *   3. Write CMD_READ to CMD
 *   4. Read 4 bytes at a time from the DATA register
 *
 * The device handles the cursor internally so each write/read to
 * DATA advances to the next 4 bytes automatically.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#include "secure_storage.h"
#include "uart.h"

/* -------------------------------------------------------------------------
 * MMIO register access helpers
 *
 * These write/read a 32-bit value to/from a specific register offset
 * in the device. We add the offset to the base address and do a
 * volatile pointer dereference.
 *
 * volatile is critical here, same reason as with the UART. Without it
 * the compiler might optimize away repeated writes to the same address
 * but every write to the DATA register has a real effect on the device.
 * ------------------------------------------------------------------------- */
static void ss_reg_write(uint32_t offset, uint32_t value)
{
    volatile uint32_t *reg = (volatile uint32_t *)(SS_MMIO_BASE + offset);
    *reg = value;
}

static uint32_t ss_reg_read(uint32_t offset)
{
    volatile uint32_t *reg = (volatile uint32_t *)(SS_MMIO_BASE + offset);
    return *reg;
}

/* -------------------------------------------------------------------------
 * ss_init - prepare the storage
 *
 * Erase all slots in the device so we start clean. We could skip
 * this if we wanted to keep data across reboots (once we add
 * persistence), but for now we start fresh every time.
 * ------------------------------------------------------------------------- */
void ss_init(void)
{
    int i;

    uart_puts("[SS] Initializing Secure Storage (MMIO backend)...\n");
    uart_puts("[SS] Device address: ");
    uart_put_hex(SS_MMIO_BASE);
    uart_puts("\n");

    /*
     * Check how many slots already have data from a previous boot.
     * If the QEMU device loaded a backing file, some slots will
     * already be populated. We do NOT erase them because that would
     * destroy persisted keys (SRS-D-001).
     */
    {
        int populated = 0;
        for (i = 0; i < SS_NUM_SLOTS; i++) {
            ss_reg_write(SS_REG_SLOT_ID, i);
            ss_reg_write(SS_REG_CMD, SS_CMD_CHECK);
            if (ss_reg_read(SS_REG_STATUS) == SS_STATUS_HAS_DATA) {
                populated++;
            }
        }
        if (populated > 0) {
            uart_puts("[SS] Found ");
            uart_put_hex(populated);
            uart_puts(" slots with persisted data\n");
        }
    }

    uart_puts("[SS] ");
    uart_put_hex(SS_NUM_SLOTS);
    uart_puts(" slots available, each up to ");
    uart_put_hex(SS_MAX_KEY_SIZE);
    uart_puts(" bytes\n");
    uart_puts("[SS] Secure Storage ready\n");
}

/* -------------------------------------------------------------------------
 * ss_write_key - store data in a slot via MMIO
 *
 * Sends the data 4 bytes at a time through the DATA register.
 * The device cursor advances automatically after each write.
 * ------------------------------------------------------------------------- */
int ss_write_key(key_id_t id, const uint8_t *data, uint32_t size)
{
    uint32_t i;
    uint32_t word;

    if (id >= KEY_ID_MAX) {
        uart_puts("[SS] ERROR: invalid key ID\n");
        return -1;
    }
    if (size > SS_MAX_KEY_SIZE) {
        uart_puts("[SS] ERROR: data too large\n");
        return -1;
    }

    /* tell the device which slot and where to start */
    ss_reg_write(SS_REG_SLOT_ID, id);
    ss_reg_write(SS_REG_OFFSET, 0);
    ss_reg_write(SS_REG_SIZE, size);

    /* send the WRITE command, device prepares its internal cursor */
    ss_reg_write(SS_REG_CMD, SS_CMD_WRITE);

    /* check if the device accepted the command */
    if (ss_reg_read(SS_REG_STATUS) != SS_STATUS_OK) {
        uart_puts("[SS] ERROR: device rejected write command\n");
        return -1;
    }

    /*
     * Feed data 4 bytes at a time through the DATA register.
     * We pack each group of up to 4 bytes into a 32-bit word.
     * If the total size is not a multiple of 4, the last word
     * just has fewer valid bytes (the device knows from SIZE).
     */
    for (i = 0; i < size; i += 4) {
        word = 0;
        if (i + 0 < size) word |= ((uint32_t)data[i + 0]) << 0;
        if (i + 1 < size) word |= ((uint32_t)data[i + 1]) << 8;
        if (i + 2 < size) word |= ((uint32_t)data[i + 2]) << 16;
        if (i + 3 < size) word |= ((uint32_t)data[i + 3]) << 24;
        ss_reg_write(SS_REG_DATA, word);
    }

    uart_puts("[SS] Key written to slot ");
    uart_put_hex(id);
    uart_puts(" (");
    uart_put_hex(size);
    uart_puts(" bytes)\n");

    return 0;
}

/* -------------------------------------------------------------------------
 * ss_read_key - read data from a slot via MMIO
 *
 * Reads 4 bytes at a time from the DATA register and unpacks them
 * into the caller's buffer.
 * ------------------------------------------------------------------------- */
int ss_read_key(key_id_t id, uint8_t *data, uint32_t *size)
{
    uint32_t i, stored_size, word;

    if (id >= KEY_ID_MAX) {
        uart_puts("[SS] ERROR: invalid key ID\n");
        return -1;
    }

    /* check if the slot has data */
    ss_reg_write(SS_REG_SLOT_ID, id);
    ss_reg_write(SS_REG_CMD, SS_CMD_CHECK);

    if (ss_reg_read(SS_REG_STATUS) != SS_STATUS_HAS_DATA) {
        uart_puts("[SS] ERROR: slot ");
        uart_put_hex(id);
        uart_puts(" is empty\n");
        return -1;
    }

    /* read the stored size from the device */
    stored_size = ss_reg_read(SS_REG_SIZE);
    *size = stored_size;

    /* set up for reading */
    ss_reg_write(SS_REG_SLOT_ID, id);
    ss_reg_write(SS_REG_OFFSET, 0);
    ss_reg_write(SS_REG_CMD, SS_CMD_READ);

    if (ss_reg_read(SS_REG_STATUS) != SS_STATUS_OK) {
        uart_puts("[SS] ERROR: device rejected read command\n");
        return -1;
    }

    /* pull data 4 bytes at a time from the DATA register */
    for (i = 0; i < stored_size; i += 4) {
        word = ss_reg_read(SS_REG_DATA);
        if (i + 0 < stored_size) data[i + 0] = (uint8_t)(word >> 0);
        if (i + 1 < stored_size) data[i + 1] = (uint8_t)(word >> 8);
        if (i + 2 < stored_size) data[i + 2] = (uint8_t)(word >> 16);
        if (i + 3 < stored_size) data[i + 3] = (uint8_t)(word >> 24);
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * ss_key_exists - check if a slot has data
 * ------------------------------------------------------------------------- */
int ss_key_exists(key_id_t id)
{
    if (id >= KEY_ID_MAX) return 0;

    ss_reg_write(SS_REG_SLOT_ID, id);
    ss_reg_write(SS_REG_CMD, SS_CMD_CHECK);

    return (ss_reg_read(SS_REG_STATUS) == SS_STATUS_HAS_DATA);
}

/* -------------------------------------------------------------------------
 * ss_delete_key - wipe a slot
 * ------------------------------------------------------------------------- */
int ss_delete_key(key_id_t id)
{
    if (id >= KEY_ID_MAX) return -1;

    ss_reg_write(SS_REG_SLOT_ID, id);
    ss_reg_write(SS_REG_CMD, SS_CMD_ERASE);

    uart_puts("[SS] Slot ");
    uart_put_hex(id);
    uart_puts(" wiped\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * ss_dump - print summary of all slots
 * ------------------------------------------------------------------------- */
void ss_dump(void)
{
    int i, j;
    uint8_t buf[SS_MAX_KEY_SIZE];
    uint32_t sz;

    uart_puts("[SS] === Storage dump ===\n");
    for (i = 0; i < SS_NUM_SLOTS; i++) {
        uart_puts("[SS]  Slot ");
        uart_put_hex(i);

        if (!ss_key_exists(i)) {
            uart_puts(": empty\n");
        } else {
            ss_read_key(i, buf, &sz);
            uart_puts(": ");
            uart_put_hex(sz);
            uart_puts(" bytes = ");
            for (j = 0; j < 8 && j < (int)sz; j++) {
                uart_put_hex(buf[j]);
                uart_puts(" ");
            }
            if (sz > 8) uart_puts("...");
            uart_puts("\n");
        }
    }
    uart_puts("[SS] === End dump ===\n");
}
