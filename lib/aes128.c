/* ==========================================================================
 * aes128.c - AES-128 block cipher implementation
 * ==========================================================================
 *
 * Standalone AES-128 following FIPS 197. No external dependencies.
 *
 * How AES works at a high level:
 *   1. The 16-byte key is "expanded" into 11 round keys (176 bytes)
 *   2. The 16-byte plaintext is arranged as a 4x4 grid of bytes
 *   3. We XOR the grid with the first round key
 *   4. Then for 10 rounds we apply 4 operations:
 *      - SubBytes: replace each byte using a lookup table (the S-box)
 *      - ShiftRows: rotate each row of the grid by different amounts
 *      - MixColumns: mix the columns using polynomial multiplication
 *      - AddRoundKey: XOR with the next round key
 *   5. The last round skips MixColumns
 *   6. The result is the 16-byte ciphertext
 *
 * Decryption is the same operations in reverse, using the inverse
 * S-box and inverse MixColumns.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#include "aes128.h"

/* -------------------------------------------------------------------------
 * S-box: the substitution table used in SubBytes
 *
 * Each byte of the input is replaced with the corresponding byte
 * in this table. For example, if the input byte is 0x53, we look
 * up sbox[0x53] = 0xed. This provides non-linearity which is
 * essential for security.
 *
 * The S-box is derived from the multiplicative inverse in GF(2^8)
 * followed by an affine transformation. We just store the result
 * as a lookup table since computing it on the fly is expensive.
 * ------------------------------------------------------------------------- */
static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* -------------------------------------------------------------------------
 * Inverse S-box for decryption (InvSubBytes)
 * ------------------------------------------------------------------------- */
static const uint8_t inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

/* -------------------------------------------------------------------------
 * Round constants for key expansion
 * Each round of key expansion uses a different constant.
 * These come from powers of x in GF(2^8).
 * ------------------------------------------------------------------------- */
static const uint8_t rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* -------------------------------------------------------------------------
 * Key expansion: turn the 16-byte key into 176 bytes of round keys
 *
 * The first 16 bytes are just the original key. Then each new
 * 4-byte word is computed from the previous word and the word
 * 4 positions back, with some S-box substitution and XOR with
 * round constants thrown in every 4th word.
 * ------------------------------------------------------------------------- */
void aes128_init(aes128_context *ctx, const uint8_t key[AES_KEY_SIZE])
{
    uint8_t temp[4];
    int i;

    /* first round key is the key itself */
    for (i = 0; i < AES_KEY_SIZE; i++) {
        ctx->round_keys[i] = key[i];
    }

    /* generate the remaining round keys */
    for (i = AES_KEY_SIZE; i < 176; i += 4) {
        /* copy the previous word */
        temp[0] = ctx->round_keys[i - 4];
        temp[1] = ctx->round_keys[i - 3];
        temp[2] = ctx->round_keys[i - 2];
        temp[3] = ctx->round_keys[i - 1];

        /* every 4th word (16 bytes) gets special treatment */
        if (i % AES_KEY_SIZE == 0) {
            /* RotWord: rotate left by 1 byte */
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            /* SubWord: apply S-box to each byte */
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];

            /* XOR with round constant */
            temp[0] ^= rcon[(i / AES_KEY_SIZE) - 1];
        }

        /* XOR with the word 16 bytes back */
        ctx->round_keys[i + 0] = ctx->round_keys[i - AES_KEY_SIZE + 0] ^ temp[0];
        ctx->round_keys[i + 1] = ctx->round_keys[i - AES_KEY_SIZE + 1] ^ temp[1];
        ctx->round_keys[i + 2] = ctx->round_keys[i - AES_KEY_SIZE + 2] ^ temp[2];
        ctx->round_keys[i + 3] = ctx->round_keys[i - AES_KEY_SIZE + 3] ^ temp[3];
    }
}

/* -------------------------------------------------------------------------
 * Galois Field multiplication helpers for MixColumns
 *
 * In AES, MixColumns multiplies bytes in GF(2^8) with the
 * irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).
 * xtime() multiplies by x (i.e. by 2 in GF(2^8)).
 * ------------------------------------------------------------------------- */
static uint8_t xtime(uint8_t x)
{
    return (x << 1) ^ ((x & 0x80) ? 0x1b : 0x00);
}

/* multiply by 2 in GF(2^8) */
#define GF_MUL2(x) xtime(x)
/* multiply by 3 = multiply by 2 then XOR with original */
#define GF_MUL3(x) (xtime(x) ^ (x))

/* for decryption we need multiply by 9, 11, 13, 14 */
static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t result = 0;
    uint8_t hi;
    int i;
    for (i = 0; i < 8; i++) {
        if (b & 1) result ^= a;
        hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return result;
}

/* -------------------------------------------------------------------------
 * aes128_encrypt_block - encrypt one 16-byte block
 * ------------------------------------------------------------------------- */
void aes128_encrypt_block(const aes128_context *ctx,
                          const uint8_t input[AES_BLOCK_SIZE],
                          uint8_t output[AES_BLOCK_SIZE])
{
    uint8_t state[16];
    int i, round;
    uint8_t t;

    /* copy input to state */
    for (i = 0; i < 16; i++) state[i] = input[i];

    /* initial round key addition */
    for (i = 0; i < 16; i++) state[i] ^= ctx->round_keys[i];

    /* 10 rounds */
    for (round = 1; round <= AES_NUM_ROUNDS; round++) {
        /* SubBytes: replace each byte through S-box */
        for (i = 0; i < 16; i++) state[i] = sbox[state[i]];

        /* ShiftRows: rotate rows of the 4x4 state matrix
         * Row 0: no shift
         * Row 1: shift left by 1
         * Row 2: shift left by 2
         * Row 3: shift left by 3
         * State is stored column-major: state[row + 4*col] */
        t = state[1]; state[1] = state[5]; state[5] = state[9];
        state[9] = state[13]; state[13] = t;

        t = state[2]; state[2] = state[10]; state[10] = t;
        t = state[6]; state[6] = state[14]; state[14] = t;

        t = state[3]; state[3] = state[15]; state[15] = state[11];
        state[11] = state[7]; state[7] = t;

        /* MixColumns: mix each column (skip in last round) */
        if (round < AES_NUM_ROUNDS) {
            for (i = 0; i < 16; i += 4) {
                uint8_t a = state[i], b = state[i+1],
                        c = state[i+2], d = state[i+3];
                state[i]   = GF_MUL2(a) ^ GF_MUL3(b) ^ c ^ d;
                state[i+1] = a ^ GF_MUL2(b) ^ GF_MUL3(c) ^ d;
                state[i+2] = a ^ b ^ GF_MUL2(c) ^ GF_MUL3(d);
                state[i+3] = GF_MUL3(a) ^ b ^ c ^ GF_MUL2(d);
            }
        }

        /* AddRoundKey */
        for (i = 0; i < 16; i++)
            state[i] ^= ctx->round_keys[round * 16 + i];
    }

    /* copy state to output */
    for (i = 0; i < 16; i++) output[i] = state[i];
}

/* -------------------------------------------------------------------------
 * aes128_decrypt_block - decrypt one 16-byte block
 * ------------------------------------------------------------------------- */
void aes128_decrypt_block(const aes128_context *ctx,
                          const uint8_t input[AES_BLOCK_SIZE],
                          uint8_t output[AES_BLOCK_SIZE])
{
    uint8_t state[16];
    int i, round;
    uint8_t t;

    for (i = 0; i < 16; i++) state[i] = input[i];

    /* initial round key (last round key) */
    for (i = 0; i < 16; i++)
        state[i] ^= ctx->round_keys[AES_NUM_ROUNDS * 16 + i];

    for (round = AES_NUM_ROUNDS - 1; round >= 0; round--) {
        /* InvShiftRows */
        t = state[13]; state[13] = state[9]; state[9] = state[5];
        state[5] = state[1]; state[1] = t;

        t = state[2]; state[2] = state[10]; state[10] = t;
        t = state[6]; state[6] = state[14]; state[14] = t;

        t = state[7]; state[7] = state[11]; state[11] = state[15];
        state[15] = state[3]; state[3] = t;

        /* InvSubBytes */
        for (i = 0; i < 16; i++) state[i] = inv_sbox[state[i]];

        /* AddRoundKey */
        for (i = 0; i < 16; i++)
            state[i] ^= ctx->round_keys[round * 16 + i];

        /* InvMixColumns (skip in first round, i.e. round 0) */
        if (round > 0) {
            for (i = 0; i < 16; i += 4) {
                uint8_t a = state[i], b = state[i+1],
                        c = state[i+2], d = state[i+3];
                state[i]   = gf_mul(a,14) ^ gf_mul(b,11) ^ gf_mul(c,13) ^ gf_mul(d,9);
                state[i+1] = gf_mul(a,9)  ^ gf_mul(b,14) ^ gf_mul(c,11) ^ gf_mul(d,13);
                state[i+2] = gf_mul(a,13) ^ gf_mul(b,9)  ^ gf_mul(c,14) ^ gf_mul(d,11);
                state[i+3] = gf_mul(a,11) ^ gf_mul(b,13) ^ gf_mul(c,9)  ^ gf_mul(d,14);
            }
        }
    }

    for (i = 0; i < 16; i++) output[i] = state[i];
}

/* -------------------------------------------------------------------------
 * aes128_encrypt / aes128_decrypt - ECB mode for multiple blocks
 * ------------------------------------------------------------------------- */
void aes128_encrypt(const aes128_context *ctx,
                    const uint8_t *data, uint8_t *out, uint32_t len)
{
    uint32_t i;
    for (i = 0; i < len; i += AES_BLOCK_SIZE) {
        aes128_encrypt_block(ctx, &data[i], &out[i]);
    }
}

void aes128_decrypt(const aes128_context *ctx,
                    const uint8_t *data, uint8_t *out, uint32_t len)
{
    uint32_t i;
    for (i = 0; i < len; i += AES_BLOCK_SIZE) {
        aes128_decrypt_block(ctx, &data[i], &out[i]);
    }
}
