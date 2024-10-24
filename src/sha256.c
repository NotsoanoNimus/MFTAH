/*
 * This code was taken and modified from commit b29613850d6e54e7159197ef42c7d22d012b6367 of
 *   https://github.com/amosnier/sha-2. It has been heavily modified to suit this project.
 * 
 * Here is the project's Zero Clause BSD License:
 * 
 * © 2021 Alain Mosnier
 *
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or
 * without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
 * USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"


#include "include/mftah.h"


/*
 * @brief Size of the SHA-256 sum. This times eight is 256 bits.
 */
#define SIZE_OF_SHA_256_HASH 32

/*
 * @brief Size of the chunks used for the calculations.
 *
 * @note This should mostly be ignored by the user, although when using the streaming API, it has an impact for
 * performance. Add chunks whose size is a multiple of this, and you will avoid a lot of superfluous copying in RAM!
 */
#define SIZE_OF_SHA_256_CHUNK 64

/*
 * @brief The opaque SHA-256 type, that should be instantiated when using the streaming API.
 *
 * @note Although the details are exposed here, in order to make instantiation easy, you should refrain from directly
 * accessing the fields, as they may change in the future.
 */
struct Sha_256 {
	uint8_t *hash;
	uint8_t  chunk[SIZE_OF_SHA_256_CHUNK];
	uint8_t *chunk_pos;
	size_t   space_left;
	uint64_t total_len;
	uint32_t h[8];
};


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
static
void
calc_sha_256(
    mftah_immutable_protocol_t mftah,
    uint8_t hash[SIZE_OF_SHA_256_HASH],
    const void *input,
    size_t len
);


/*
 * @brief Initialize a SHA-256 streaming calculation.
 * @param sha_256 A pointer to a SHA-256 structure.
 * @param hash Hash array, where the result will be delivered.
 *
 * @note If all of the data you are calculating the hash value on is not available in a contiguous buffer in memory,
 * this is where you should start. Instantiate a SHA-256 structure, for instance by simply declaring it locally, make
 * your hash buffer available, and invoke this function. Once a SHA-256 hash has been calculated (see further below) a
 * SHA-256 structure can be initialized again for the next calculation.
 *
 * @note If either of the passed pointers is NULL, the results are unpredictable.
 */
static
void
sha_256_init(
    struct Sha_256 *sha_256,
    uint8_t hash[SIZE_OF_SHA_256_HASH]
);


/*
 * @brief Stream more input data for an on-going SHA-256 calculation.
 * @param sha_256 A pointer to a previously initialized SHA-256 structure.
 * @param data Pointer to the data to be added to the calculation.
 * @param len Length of the data to add, in byte.
 *
 * @note This function may be invoked an arbitrary number of times between initialization and closing, but the maximum
 * data length is limited by the SHA-256 algorithm: the total number of bits (i.e. the total number of bytes times
 * eight) must be representable by a 64-bit unsigned integer. While that is not a practical limitation, the results are
 * unpredictable if that limit is exceeded.
 *
 * @note This function may be invoked on empty data (zero length), although that obviously will not add any data.
 *
 * @note If either of the passed pointers is NULL, the results are unpredictable.
 */
static
void
sha_256_write(
    mftah_immutable_protocol_t mftah,
    struct Sha_256 *sha_256,
    const void *data,
    size_t len
);


/*
 * @brief Conclude a SHA-256 streaming calculation, making the hash value available.
 * @param sha_256 A pointer to a previously initialized SHA-256 structure.
 * @return Pointer to the hash array, where the result is delivered.
 *
 * @note After this function has been invoked, the result is available in the hash buffer that initially was provided. A
 * pointer to the hash value is returned for convenience, but you should feel free to ignore it: it is simply a pointer
 * to the first byte of your initially provided hash array.
 *
 * @note If the passed pointer is NULL, the results are unpredictable.
 *
 * @note Invoking this function for a calculation with no data (the writing function has never been invoked, or it only
 * has been invoked with empty data) is legal. It will calculate the SHA-256 value of the empty string.
 */
static
uint8_t *
sha_256_close(
    mftah_immutable_protocol_t mftah,
    struct Sha_256 *sha_256
);


/* Additional HMAC_SHA256 implementation. */
static
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


/* Custom */
typedef
struct {
    uint8_t k[SIZE_OF_SHA_256_CHUNK];
    uint8_t k_ipad[SIZE_OF_SHA_256_CHUNK];
    uint8_t k_opad[SIZE_OF_SHA_256_CHUNK];
    struct Sha_256 inner_sha_ctx;
    struct Sha_256 outer_sha_ctx;
    uint8_t inner[SIZE_OF_SHA_256_HASH];
    uint8_t outer[SIZE_OF_SHA_256_HASH];
} hmac_sha_256_ctx;


static
void
hmac_sha256_init(
    mftah_immutable_protocol_t mftah,
    hmac_sha_256_ctx *ctx,
    const void *key,
    const size_t key_length
);

static
void
hmac_sha256_write(
    mftah_immutable_protocol_t mftah,
    hmac_sha_256_ctx *ctx,
    const void *data,
    const size_t data_length
);

static
void
hmac_sha256_close(
    mftah_immutable_protocol_t mftah,
    hmac_sha_256_ctx *ctx,
    void *out
);


#define TOTAL_LEN_LEN 8


/*
 * @brief Rotate a 32-bit value by a number of bits to the right.
 * @param value The value to be rotated.
 * @param count The number of bits to rotate by.
 * @return The rotated value.
 */
static inline
uint32_t
right_rot(uint32_t value,
          unsigned int count)
{
    /*
     * Defined behaviour in standard C for all count where 0 < count < 32, which is what we need here.
     */
    return value >> count | value << (32 - count);
}


/*
 * @brief Update a hash value under calculation with a new chunk of data.
 * @param h Pointer to the first hash item, of a total of eight.
 * @param p Pointer to the chunk data, which has a standard length.
 *
 * @note This is the SHA-256 work horse.
 */
static inline
void
consume_chunk(uint32_t *h,
              const uint8_t *p)
{
    unsigned i, j;
    uint32_t ah[8];

    /* Initialize working variables to current hash value: */
    for (i = 0; i < 8; i++)
        ah[i] = h[i];

    /*
     * The w-array is really w[64], but since we only need 16 of them at a time, we save stack by
     * calculating 16 at a time.
     *
     * This optimization was not there initially and the rest of the comments about w[64] are kept in their
     * initial state.
     */

    /*
     * create a 64-entry message schedule array w[0..63] of 32-bit words (The initial values in w[0..63]
     * don't matter, so many implementations zero them here) copy chunk into first 16 words w[0..15] of the
     * message schedule array
     */
    uint32_t w[16];

    /* Compression function main loop: */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 16; j++) {
            if (i == 0) {
                w[j] =
                    (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3];
                p += 4;
            } else {
                /* Extend the first 16 words into the remaining 48 words w[16..63] of the
                 * message schedule array: */
                const uint32_t s0 = right_rot(w[(j + 1) & 0xf], 7) ^ right_rot(w[(j + 1) & 0xf], 18) ^
                            (w[(j + 1) & 0xf] >> 3);
                const uint32_t s1 = right_rot(w[(j + 14) & 0xf], 17) ^
                            right_rot(w[(j + 14) & 0xf], 19) ^ (w[(j + 14) & 0xf] >> 10);
                w[j] = w[j] + s0 + w[(j + 9) & 0xf] + s1;
            }
            const uint32_t s1 = right_rot(ah[4], 6) ^ right_rot(ah[4], 11) ^ right_rot(ah[4], 25);
            const uint32_t ch = (ah[4] & ah[5]) ^ (~ah[4] & ah[6]);

            /*
             * Initialize array of round constants:
             * (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
             */
            static const uint32_t k[] = {
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
                0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
                0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
                0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
                0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
                0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
                0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
                0xc67178f2
            };

            const uint32_t temp1 = ah[7] + s1 + ch + k[i << 4 | j] + w[j];
            const uint32_t s0 = right_rot(ah[0], 2) ^ right_rot(ah[0], 13) ^ right_rot(ah[0], 22);
            const uint32_t maj = (ah[0] & ah[1]) ^ (ah[0] & ah[2]) ^ (ah[1] & ah[2]);
            const uint32_t temp2 = s0 + maj;

            ah[7] = ah[6];
            ah[6] = ah[5];
            ah[5] = ah[4];
            ah[4] = ah[3] + temp1;
            ah[3] = ah[2];
            ah[2] = ah[1];
            ah[1] = ah[0];
            ah[0] = temp1 + temp2;
        }
    }

    /* Add the compressed chunk to the current hash value: */
    for (i = 0; i < 8; i++)
        h[i] += ah[i];
}


static
void
sha_256_init(struct Sha_256 *sha_256,
             uint8_t hash[SIZE_OF_SHA_256_HASH])
{
    sha_256->hash = hash;
    sha_256->chunk_pos = sha_256->chunk;
    sha_256->space_left = SIZE_OF_SHA_256_CHUNK;
    sha_256->total_len = 0;

    /*
     * Initialize hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes
     * 2..19):
     */
    sha_256->h[0] = 0x6a09e667;
    sha_256->h[1] = 0xbb67ae85;
    sha_256->h[2] = 0x3c6ef372;
    sha_256->h[3] = 0xa54ff53a;
    sha_256->h[4] = 0x510e527f;
    sha_256->h[5] = 0x9b05688c;
    sha_256->h[6] = 0x1f83d9ab;
    sha_256->h[7] = 0x5be0cd19;
}


static
void
sha_256_write(mftah_immutable_protocol_t mftah,
              struct Sha_256 *sha_256,
              const void *data,
              size_t len)
{
    sha_256->total_len += len;

    /*
     * The following cast is not necessary, and could even be considered as poor practice. However, it makes this
     * file valid C++, which could be a good thing for some use cases.
     */
    const uint8_t *p = (const uint8_t *)data;

    while (len > 0) {
        /*
         * If the input chunks have sizes that are multiples of the calculation chunk size, no copies are
         * necessary. We operate directly on the input data instead.
         */
        if (sha_256->space_left == SIZE_OF_SHA_256_CHUNK && len >= SIZE_OF_SHA_256_CHUNK) {
            consume_chunk(sha_256->h, p);
            len -= SIZE_OF_SHA_256_CHUNK;
            p += SIZE_OF_SHA_256_CHUNK;
            continue;
        }
        /* General case, no particular optimization. */
        const size_t consumed_len = len < sha_256->space_left ? len : sha_256->space_left;
        mftah->hooks.memcpy(sha_256->chunk_pos, p, consumed_len);
        sha_256->space_left -= consumed_len;
        len -= consumed_len;
        p += consumed_len;
        if (sha_256->space_left == 0) {
            consume_chunk(sha_256->h, sha_256->chunk);
            sha_256->chunk_pos = sha_256->chunk;
            sha_256->space_left = SIZE_OF_SHA_256_CHUNK;
        } else {
            sha_256->chunk_pos += consumed_len;
        }
    }
}


static
uint8_t *
sha_256_close(mftah_immutable_protocol_t mftah,
              struct Sha_256 *sha_256)
{
    uint8_t *pos = sha_256->chunk_pos;
    size_t space_left = sha_256->space_left;
    uint32_t *const h = sha_256->h;

    /*
     * The current chunk cannot be full. Otherwise, it would already have been consumed. I.e. there is space left
     * for at least one byte. The next step in the calculation is to add a single one-bit to the data.
     */
    *pos++ = 0x80;
    --space_left;

    /*
     * Now, the last step is to add the total data length at the end of the last chunk, and zero padding before
     * that. But we do not necessarily have enough space left. If not, we pad the current chunk with zeroes, and add
     * an extra chunk at the end.
     */
    if (space_left < TOTAL_LEN_LEN) {
        mftah->hooks.memset(pos, 0x00, space_left);
        consume_chunk(h, sha_256->chunk);
        pos = sha_256->chunk;
        space_left = SIZE_OF_SHA_256_CHUNK;
    }
    const size_t left = space_left - TOTAL_LEN_LEN;
    mftah->hooks.memset(pos, 0x00, left);
    pos += left;
    uint64_t len = sha_256->total_len;
    pos[7] = (uint8_t)(len << 3);
    len >>= 5;
    int i;
    for (i = 6; i >= 0; --i) {
        pos[i] = (uint8_t)len;
        len >>= 8;
    }
    consume_chunk(h, sha_256->chunk);
    /* Produce the final hash value (big-endian): */
    int j;
    uint8_t *const hash = sha_256->hash;
    for (i = 0, j = 0; i < 8; i++) {
        hash[j++] = (uint8_t)(h[i] >> 24);
        hash[j++] = (uint8_t)(h[i] >> 16);
        hash[j++] = (uint8_t)(h[i] >> 8);
        hash[j++] = (uint8_t)h[i];
    }
    return sha_256->hash;
}


static
void
calc_sha_256(mftah_immutable_protocol_t mftah,
             uint8_t hash[SIZE_OF_SHA_256_HASH],
             const void *input,
             size_t len)
{
    struct Sha_256 sha_256;
    sha_256_init(&sha_256, hash);
    sha_256_write(mftah, &sha_256, input, len);
    (void)sha_256_close(mftah, &sha_256);
}



/* Concatenate X & Y, return hash. */
static inline
void
H(mftah_immutable_protocol_t mftah,
  const void* x,
  const size_t xlen,
  const void* y,
  const size_t ylen,
  void* out,
  const size_t outlen)
{
    struct Sha_256 sha;
    sha_256_init(&sha, out);

    sha_256_write(mftah, &sha, x, xlen);
    sha_256_write(mftah, &sha, y, ylen);

    sha_256_close(mftah, &sha);
}


/* Added here as an addition to SHA-256 methods. */
static
void
hmac_sha256(mftah_immutable_protocol_t mftah,
            const void* key,
            const size_t keylen,
            const void* data,
            const size_t datalen,
            void* out)
{
    uint8_t k[SIZE_OF_SHA_256_CHUNK];
    uint8_t k_ipad[SIZE_OF_SHA_256_CHUNK];
    uint8_t k_opad[SIZE_OF_SHA_256_CHUNK];
    uint8_t ihash[SIZE_OF_SHA_256_HASH];
    uint8_t ohash[SIZE_OF_SHA_256_HASH];
    int i;

    mftah->hooks.memset(k, 0, sizeof(k));
    mftah->hooks.memset(k_ipad, 0x36, SIZE_OF_SHA_256_CHUNK);
    mftah->hooks.memset(k_opad, 0x5c, SIZE_OF_SHA_256_CHUNK);

    if (keylen > SIZE_OF_SHA_256_CHUNK) {
        /* If the key is larger than the hash algorithm's block size, we must digest it first. */
        calc_sha_256(mftah, k, key, keylen);
    } else {
        mftah->hooks.memcpy(k, key, keylen);
    }

    for (i = 0; i < SIZE_OF_SHA_256_CHUNK; i++) {
        k_ipad[i] ^= k[i];
        k_opad[i] ^= k[i];
    }

    /* Perform HMAC algorithm: (https://tools.ietf.org/html/rfc2104) `H(K XOR opad, H(K XOR ipad, data))` */
    H(mftah, k_ipad, sizeof(k_ipad), data, datalen, ihash, sizeof(ihash));
    H(mftah, k_opad, sizeof(k_opad), ihash, sizeof(ihash), ohash, sizeof(ohash));

    mftah->hooks.memcpy(out, ohash, SIZE_OF_SHA_256_HASH);
}


/* CUSTOM */
static
void
hmac_sha256_init(mftah_immutable_protocol_t mftah,
                 hmac_sha_256_ctx *ctx,
                 const void *key,
                 const size_t key_length)
{
    if (NULL == ctx) return;

    mftah->hooks.memset(ctx->k, 0, sizeof(ctx->k));
    mftah->hooks.memset(ctx->k_ipad, 0x36, SIZE_OF_SHA_256_CHUNK);
    mftah->hooks.memset(ctx->k_opad, 0x5c, SIZE_OF_SHA_256_CHUNK);

    if (key_length > SIZE_OF_SHA_256_CHUNK) {
        /* If the key is larger than the hash algorithm's block size, we must digest it first. */
        calc_sha_256(mftah, ctx->k, key, key_length);
    } else {
        mftah->hooks.memcpy(ctx->k, key, key_length);
    }

    for (int i = 0; i < SIZE_OF_SHA_256_CHUNK; i++) {
        ctx->k_ipad[i] ^= ctx->k[i];
        ctx->k_opad[i] ^= ctx->k[i];
    }

    sha_256_init(&ctx->inner_sha_ctx, ctx->inner);
    sha_256_write(mftah, &ctx->inner_sha_ctx, ctx->k_ipad, sizeof(ctx->k_ipad));

    sha_256_init(&ctx->outer_sha_ctx, ctx->outer);
    sha_256_write(mftah, &ctx->outer_sha_ctx, ctx->k_opad, sizeof(ctx->k_opad));
}


static
void
hmac_sha256_write(mftah_immutable_protocol_t mftah,
                  hmac_sha_256_ctx *ctx,
                  const void *data,
                  const size_t data_length)
{
    sha_256_write(mftah, &ctx->inner_sha_ctx, data, data_length);
}


static
void
hmac_sha256_close(mftah_immutable_protocol_t mftah,
                  hmac_sha_256_ctx *ctx,
                  void *out)
{
    sha_256_write(mftah, &ctx->outer_sha_ctx, ctx->inner, SIZE_OF_SHA_256_HASH);

    sha_256_close(mftah, &ctx->inner_sha_ctx);
    sha_256_close(mftah, &ctx->outer_sha_ctx);

    mftah->hooks.memcpy(out, ctx->outer, SIZE_OF_SHA_256_HASH);
}



#pragma GCC diagnostic pop
