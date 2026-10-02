#ifndef LIBMFTAH_SHA256_H
#define LIBMFTAH_SHA256_H

#include "mftah.h"


/*
 * @brief Size of the SHA-256 sum. This times eight is 256 bits.
 */
#define SIZE_OF_SHA_256_HASH 32


/*
 * @brief The simple SHA-256 calculation function.
 * @param hash Hash array, where the result is delivered.
 * @param input Pointer to the data the hash shall be calculated on.
 * @param len Length of the input data, in byte.
 *
 * @note If all of the data you are calculating the hash value on is available in a contiguous buffer in memory, this is
 * the function you should use.
 *
 * @note If either of the passed pointers is NULL, the results are unpredictable.
 *
 * @note See note about maximum data length for sha_256_write, as it applies for this function's len argument too.
 */
void
calc_sha_256(
    mftah_immutable_protocol_t mftah,
    uint8_t hash[SIZE_OF_SHA_256_HASH],
    const void *input,
    size_t len
);


/* Additional HMAC_SHA256 implementation. */
void
hmac_sha256(
    mftah_immutable_protocol_t mftah,
    /* The key and its length. */
    const void* key,
    const size_t keylen,
    /* The data and its length. */
    const void* data,
    const size_t datalen,
    /* The resultant hash buffer. Always 32 bytes long. */
    void* out
);


#endif   /* LIBMFTAH_SHA256_H */
