#ifndef LIBMFTAH_AES_H
#define LIBMFTAH_AES_H

#include <stdint.h>
#include <stddef.h>


#define AES_keyExpSize	240
#define AES_BLOCKLEN	16
#define AES_KEYLEN		32


typedef
void *
(*aes_memcpy_fn_t)(
	void *restrict,
	const void *restrict,
	size_t
);

typedef
void
(*aes_progress_fn_t)(
	const size_t *,
	const size_t *,
	void *
);


typedef
struct AES_ctx
{
	uint8_t RoundKey[AES_keyExpSize];
	uint8_t Iv[AES_BLOCKLEN];
	aes_memcpy_fn_t MemcpyHook;
} aes_ctx_t;


/**
 * Initialize a new context with an IV.
 */
void
AES_init_ctx_iv(
	aes_ctx_t		*ctx,
	aes_memcpy_fn_t	memcpy_hook,
	const uint8_t	*key,
	const uint8_t	*iv
);

/**
 * The buffer size MUST be a mutiple of AES_BLOCKLEN.
 * NOTES:
 *   - Need to set IV in ctx via AES_init_ctx_iv()
 *   - No IV should ever be reused with the same key 
 */
void
AES_CBC_decrypt_buffer(
	aes_ctx_t			*ctx,
	uint8_t				*buf,
	uint64_t			length,
	aes_progress_fn_t	progress,
	void				*progress_extra
);

/**
 * Encrypt a buffer. It must be a multiple of AES_BLOCKLEN.
 */
void
AES_CBC_encrypt_buffer(
	aes_ctx_t			*ctx,
	uint8_t				*buf,
	uint64_t			length,
	aes_progress_fn_t	progress,
	void				*progress_extra
);


#endif   /* LIBMFTAH_AES_H */
