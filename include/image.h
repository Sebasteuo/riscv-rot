#ifndef IMAGE_H
#define IMAGE_H

#include <stdint.h>

/*
 * Signed image format for the two-stage secure boot.
 *
 * Stage-1 reads this header, hashes the payload with SHA-256 and
 * verifies an Ed25519 signature over that digest. Only if the
 * signature is valid does it transfer control to the payload.
 *
 * Layout:
 *
 *   offset  size  field
 *   0       4     magic
 *   4       4     version
 *   8       4     payload_size
 *   12      4     reserved
 *   16      64    signature (Ed25519 over the SHA-256 of the payload)
 *   80      var   payload
 */

#define IMAGE_MAGIC        0x43524F54u   /* "CROT" little-endian */
#define IMAGE_SIG_SIZE     64
#define IMAGE_HEADER_SIZE  80

/*
 * Upper bound on the payload. Stage-1 must not trust payload_size
 * blindly: an oversized value would make it hash memory outside the
 * image. The limit is checked before any hashing takes place.
 */
#define IMAGE_MAX_PAYLOAD  (1u << 20)   /* 1 MiB */

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t payload_size;
    uint32_t reserved;
    uint8_t  signature[IMAGE_SIG_SIZE];
} image_header_t;

/* Verification results, kept distinct so failures can be diagnosed */
typedef enum {
    IMAGE_OK = 0,
    IMAGE_ERR_MAGIC,
    IMAGE_ERR_SIZE,
    IMAGE_ERR_SIGNATURE,
} image_result_t;

#endif /* IMAGE_H */
