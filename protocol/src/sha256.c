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

#include "../include/sha256.h"

#define TOTAL_LEN_LEN 8


/*
 * @brief Rotate a 32-bit value by a number of bits to the right.
 * @param value The value to be rotated.
 * @param count The number of bits to rotate by.
 * @return The rotated value.
 */
static inline
uint32_t
right_rot(
	uint32_t value,
	unsigned int count
) {
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
consume_chunk(
	uint32_t *h,
	const uint8_t *p
) {
	unsigned i, j;
	uint32_t ah[8];

	/* Initialize working variables to current hash value: */
	for (i = 0; i < 8; i++) ah[i] = h[i];

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
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 16; j++)
		{
			if (i == 0)
			{
				w[j] =
					(uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3];
				p += 4;
			}
			else
			{
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
	for (i = 0; i < 8; i++) h[i] += ah[i];
}


void
sha_256_init(
	Sha256Context *ctx,
	CommonMemcpyFn memcpy,
	CommonMemsetFn memset,
	uint8_t hash[SIZE_OF_SHA_256_HASH])
{
	ctx->hash = hash;
	ctx->chunk_pos = ctx->chunk;
	ctx->space_left = SIZE_OF_SHA_256_CHUNK;
	ctx->total_len = 0;

	ctx->memcpy = memcpy;
	ctx->memset = memset;

	/*
	 * Initialize hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes
	 * 2..19):
	 */
	ctx->h[0] = 0x6a09e667;
	ctx->h[1] = 0xbb67ae85;
	ctx->h[2] = 0x3c6ef372;
	ctx->h[3] = 0xa54ff53a;
	ctx->h[4] = 0x510e527f;
	ctx->h[5] = 0x9b05688c;
	ctx->h[6] = 0x1f83d9ab;
	ctx->h[7] = 0x5be0cd19;
}


void
sha_256_write(
	Sha256Context *ctx,
	const void *data,
	size_t len
) {
	ctx->total_len += len;
	/*
	 * The following cast is not necessary, and could even be considered as poor practice. However, it makes this
	 * file valid C++, which could be a good thing for some use cases.
	 */
	const uint8_t *p = (const uint8_t *)data;
	while (len > 0)
	{
		/*
		 * If the input chunks have sizes that are multiples of the calculation chunk size, no copies are
		 * necessary. We operate directly on the input data instead.
		 */
		if (ctx->space_left == SIZE_OF_SHA_256_CHUNK && len >= SIZE_OF_SHA_256_CHUNK)
		{
			consume_chunk(ctx->h, p);
			len -= SIZE_OF_SHA_256_CHUNK;
			p += SIZE_OF_SHA_256_CHUNK;
			continue;
		}
		/* General case, no particular optimization. */
		const size_t consumed_len = len < ctx->space_left ? len : ctx->space_left;
		ctx->memcpy(ctx->chunk_pos, p, consumed_len);
		ctx->space_left -= consumed_len;
		len -= consumed_len;
		p += consumed_len;
		if (ctx->space_left == 0)
		{
			consume_chunk(ctx->h, ctx->chunk);
			ctx->chunk_pos = ctx->chunk;
			ctx->space_left = SIZE_OF_SHA_256_CHUNK;
		}
		else ctx->chunk_pos += consumed_len;
	}
}


uint8_t *
sha_256_close(
	Sha256Context *ctx
) {
	uint8_t *pos = ctx->chunk_pos;
	size_t space_left = ctx->space_left;
	uint32_t *const h = ctx->h;
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
	if (space_left < TOTAL_LEN_LEN)
	{
		ctx->memset(pos, 0x00, space_left);
		consume_chunk(h, ctx->chunk);
		pos = ctx->chunk;
		space_left = SIZE_OF_SHA_256_CHUNK;
	}
	const size_t left = space_left - TOTAL_LEN_LEN;
	ctx->memset(pos, 0x00, left);
	pos += left;
	uint64_t len = ctx->total_len;
	pos[7] = (uint8_t)(len << 3);
	len >>= 5;
	int i;
	for (i = 6; i >= 0; --i)
	{
		pos[i] = (uint8_t)len;
		len >>= 8;
	}
	consume_chunk(h, ctx->chunk);
	int j;
	uint8_t *const hash = ctx->hash;
	for (i = 0, j = 0; i < 8; i++)
	{
		hash[j++] = (uint8_t)(h[i] >> 24);
		hash[j++] = (uint8_t)(h[i] >> 16);
		hash[j++] = (uint8_t)(h[i] >> 8);
		hash[j++] = (uint8_t)h[i];
	}
	return ctx->hash;
}


void
calc_sha_256(
	CommonMemcpyFn memcpy,
	CommonMemsetFn memset,
	uint8_t hash[SIZE_OF_SHA_256_HASH],
	const void *input,
	size_t len
) {
	Sha256Context sha_256;
	sha_256_init(&sha_256, memcpy, memset, hash);
	sha_256_write(&sha_256, input, len);
	(void)sha_256_close(&sha_256);
}


/* Concatenate X & Y, return hash. */
static inline
void
H(
	CommonMemcpyFn memcpy,
	CommonMemsetFn memset,
	const void* x,
	const size_t xlen,
	const void* y,
	const size_t ylen,
	void* out,
	const size_t outlen
) {
	Sha256Context sha;
	sha_256_init(&sha, memcpy, memset, out);
	sha_256_write(&sha, x, xlen);
	sha_256_write(&sha, y, ylen);
	sha_256_close(&sha);
}


/* Added here as an addition to SHA-256 methods. */
void
hmac_sha256(
	CommonMemcpyFn memcpy,
	CommonMemsetFn memset,
	const void* key,
	const size_t keylen,
	const void* data,
	const size_t datalen,
	void* out
) {
	uint8_t k[SIZE_OF_SHA_256_CHUNK];
	uint8_t k_ipad[SIZE_OF_SHA_256_CHUNK];
	uint8_t k_opad[SIZE_OF_SHA_256_CHUNK];
	uint8_t ihash[SIZE_OF_SHA_256_HASH];
	uint8_t ohash[SIZE_OF_SHA_256_HASH];
	int i;

	memset(k, 0, sizeof(k));
	memset(k_ipad, 0x36, SIZE_OF_SHA_256_CHUNK);
	memset(k_opad, 0x5c, SIZE_OF_SHA_256_CHUNK);

	/* If the key is larger than the hash algorithm's block size, we must digest it first. */
	if (keylen > SIZE_OF_SHA_256_CHUNK)
		calc_sha_256(memcpy, memset, k, key, keylen);
	else
		memcpy(k, key, keylen);

	for (i = 0; i < SIZE_OF_SHA_256_CHUNK; i++)
	{
		k_ipad[i] ^= k[i];
		k_opad[i] ^= k[i];
	}

	/* Perform HMAC algorithm: (https://tools.ietf.org/html/rfc2104)
		`H(K XOR opad, H(K XOR ipad, data))` */
	H(memcpy, memset, k_ipad, sizeof(k_ipad), data, datalen, ihash, sizeof(ihash));
	H(memcpy, memset, k_opad, sizeof(k_opad), ihash, sizeof(ihash), ohash, sizeof(ohash));

	memcpy(out, ohash, SIZE_OF_SHA_256_HASH);
}


void
hmac_sha256_init(
	HmacSha256Context *ctx,
	CommonMemcpyFn memcpy,
	CommonMemsetFn memset,
	const void *key,
	const size_t key_length
) {
	if (NULL == ctx) return;

	ctx->memcpy = memcpy;
	ctx->memset = memset;

	ctx->memset(ctx->k, 0, sizeof(ctx->k));
	ctx->memset(ctx->k_ipad, 0x36, SIZE_OF_SHA_256_CHUNK);
	ctx->memset(ctx->k_opad, 0x5c, SIZE_OF_SHA_256_CHUNK);

	/* If the key is larger than the hash algorithm's block size, we must digest it first. */
	if (key_length > SIZE_OF_SHA_256_CHUNK)
		calc_sha_256(memcpy, memset, ctx->k, key, key_length);
	else
		ctx->memcpy(ctx->k, key, key_length);

	for (int i = 0; i < SIZE_OF_SHA_256_CHUNK; i++)
	{
		ctx->k_ipad[i] ^= ctx->k[i];
		ctx->k_opad[i] ^= ctx->k[i];
	}

	sha_256_init(&ctx->inner_sha_ctx, memcpy, memset, ctx->inner);
	sha_256_write(&ctx->inner_sha_ctx, ctx->k_ipad, sizeof(ctx->k_ipad));

	sha_256_init(&ctx->outer_sha_ctx, memcpy, memset, ctx->outer);
	sha_256_write(&ctx->outer_sha_ctx, ctx->k_opad, sizeof(ctx->k_opad));
}


void
hmac_sha256_write(
	HmacSha256Context *ctx,
	const void *data,
	const size_t data_length
) {
	sha_256_write(&ctx->inner_sha_ctx, data, data_length);
}


void
hmac_sha256_close(
	HmacSha256Context *ctx,
	void *out
) {
	sha_256_close(&ctx->inner_sha_ctx);
	sha_256_write(&ctx->outer_sha_ctx, ctx->inner, SIZE_OF_SHA_256_HASH);
	sha_256_close(&ctx->outer_sha_ctx);
	ctx->memcpy(out, ctx->outer, SIZE_OF_SHA_256_HASH);
}


#pragma GCC diagnostic pop
