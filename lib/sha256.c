/* ==========================================================================
 * sha256.c - SHA-256 implementation for bare-metal
 * ==========================================================================
 *
 * This is a clean, portable SHA-256 implementation that does not depend
 * on any standard library. It follows FIPS 180-4 exactly.
 *
 * SHA-256 works by processing the input in 64-byte (512-bit) blocks.
 * Each block goes through 64 rounds of mixing that combine the input
 * data with the current hash state. The result after all blocks is a
 * 32-byte (256-bit) digest that is unique to the input.
 *
 * The algorithm is deterministic: the same input always produces the
 * same output. But changing even one bit of the input completely
 * changes the output (avalanche effect). This is what makes it useful
 * for integrity checking.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#include "sha256.h"

/* -------------------------------------------------------------------------
 * SHA-256 constants
 *
 * These are the first 32 bits of the fractional parts of the cube roots
 * of the first 64 prime numbers. They are defined by the spec and never
 * change. They add randomness to each round of the hash computation.
 * ------------------------------------------------------------------------- */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* -------------------------------------------------------------------------
 * Bit manipulation helpers
 *
 * These are the core operations that SHA-256 uses in every round.
 * ROTR rotates bits to the right (wraps around, does not lose bits).
 * SHR shifts bits to the right (loses bits on the right side).
 * The Sigma and sigma functions combine rotations and shifts in
 * specific ways defined by the spec.
 * Ch and Maj are bitwise selection functions.
 * ------------------------------------------------------------------------- */
#define ROTR(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x, n)   ((x) >> (n))

#define S0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define s1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

#define Ch(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/* -------------------------------------------------------------------------
 * sha256_transform - process one 64-byte block
 *
 * This is the heart of SHA-256. It takes the current hash state and
 * one block of input, runs 64 rounds of mixing, and updates the state.
 *
 * First it expands the 16 input words into 64 words (the message
 * schedule W). Then it runs 64 rounds where each round mixes the
 * state using the constants K, the schedule W, and the helper
 * functions S0, S1, Ch, Maj.
 * ------------------------------------------------------------------------- */
static void sha256_transform(sha256_ctx *ctx, const uint8_t block[64])
{
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    int i;

    /* expand the 16 input words (big-endian) into 64 schedule words */
    for (i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i * 4 + 0] << 24)
             | ((uint32_t)block[i * 4 + 1] << 16)
             | ((uint32_t)block[i * 4 + 2] << 8)
             | ((uint32_t)block[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
    }

    /* initialize working variables with current hash state */
    a = ctx->state[0]; b = ctx->state[1];
    c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5];
    g = ctx->state[6]; h = ctx->state[7];

    /* 64 rounds of compression */
    for (i = 0; i < 64; i++) {
        t1 = h + S1(e) + Ch(e, f, g) + K[i] + W[i];
        t2 = S0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    /* add the compressed chunk to the current hash state */
    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
}

/* -------------------------------------------------------------------------
 * sha256_init - set up initial hash state
 *
 * These initial values are the first 32 bits of the fractional parts
 * of the square roots of the first 8 prime numbers. Defined by FIPS 180-4.
 * ------------------------------------------------------------------------- */
void sha256_init(sha256_ctx *ctx)
{
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

/* -------------------------------------------------------------------------
 * sha256_update - feed data into the hash
 *
 * Buffers partial blocks internally. When we have a full 64-byte block,
 * we process it immediately. Leftover bytes stay in the buffer until
 * the next update or final call.
 * ------------------------------------------------------------------------- */
void sha256_update(sha256_ctx *ctx, const uint8_t *data, uint32_t len)
{
    uint32_t n;
    uint32_t buf_idx = (uint32_t)(ctx->count & 0x3F);  /* position in buffer */

    ctx->count += len;

    /* Top up a partial buffer left by an earlier call */
    if (buf_idx != 0) {
        while (len > 0 && buf_idx < 64) {
            ctx->buf[buf_idx++] = *data++;
            len--;
        }
        if (buf_idx < 64) {
            return;
        }
        sha256_transform(ctx, ctx->buf);
    }

    /* Whole blocks are hashed straight from the caller buffer. The
     * transform reads a block one byte at a time, so the pointer does
     * not have to be aligned.
     */
    while (len >= 64) {
        sha256_transform(ctx, data);
        data += 64;
        len -= 64;
    }

    /* Whatever does not fill a block waits for the next call */
    for (n = 0; n < len; n++) {
        ctx->buf[n] = data[n];
    }

}

/* -------------------------------------------------------------------------
 * sha256_final - finish the hash and produce the 32-byte digest
 *
 * SHA-256 padding: append a 1 bit, then zeros, then the 64-bit length
 * in bits (big-endian). The total padded message must be a multiple of
 * 64 bytes.
 * ------------------------------------------------------------------------- */
void sha256_final(sha256_ctx *ctx, uint8_t digest[32])
{
    uint32_t buf_idx = (uint32_t)(ctx->count & 0x3F);
    uint64_t bits = ctx->count * 8;  /* length in bits */
    int i;

    /* append the 0x80 byte (a 1 bit followed by zeros) */
    ctx->buf[buf_idx++] = 0x80;

    /* if not enough room for the 8-byte length, pad and process */
    if (buf_idx > 56) {
        while (buf_idx < 64)
            ctx->buf[buf_idx++] = 0;
        sha256_transform(ctx, ctx->buf);
        buf_idx = 0;
    }

    /* pad with zeros up to byte 56 */
    while (buf_idx < 56)
        ctx->buf[buf_idx++] = 0;

    /* append the length in bits as big-endian 64-bit */
    ctx->buf[56] = (uint8_t)(bits >> 56);
    ctx->buf[57] = (uint8_t)(bits >> 48);
    ctx->buf[58] = (uint8_t)(bits >> 40);
    ctx->buf[59] = (uint8_t)(bits >> 32);
    ctx->buf[60] = (uint8_t)(bits >> 24);
    ctx->buf[61] = (uint8_t)(bits >> 16);
    ctx->buf[62] = (uint8_t)(bits >> 8);
    ctx->buf[63] = (uint8_t)(bits);

    sha256_transform(ctx, ctx->buf);

    /* write the hash state as big-endian bytes */
    for (i = 0; i < 8; i++) {
        digest[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

/* -------------------------------------------------------------------------
 * sha256 - one-shot hash function
 *
 * Convenience wrapper that does init + update + final in one call.
 * Use this when you have all the data available at once.
 * ------------------------------------------------------------------------- */
void sha256(const uint8_t *data, uint32_t len, uint8_t digest[32])
{
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}
