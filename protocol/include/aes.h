#ifndef LIBMFTAH_AES_H
#define LIBMFTAH_AES_H


#include "mftah.h"


#define AES_KEYLEN 32
#define AES_keyExpSize 240

/* Block length in bytes. 128-bit blocks only. */
#define AES_BLOCKLEN 16

typedef
struct AES_ctx {
    uint8_t RoundKey[AES_keyExpSize];
    uint8_t Iv[AES_BLOCKLEN];
} aes_ctx_t;


/**
 * Initialize a new context with an IV.
 */
void
AES_init_ctx_iv(
    const mftah_registration_details_t *meta,
    struct AES_ctx              *ctx,
    const uint8_t               *key,
    const uint8_t               *iv
);

/*
 * The buffer size MUST be a mutiple of AES_BLOCKLEN.
 * NOTES:
 *   - Need to set IV in ctx via AES_init_ctx_iv()
 *   - No IV should ever be reused with the same key 
 */
void
AES_CBC_decrypt_buffer(
    const mftah_registration_details_t *meta,
    struct AES_ctx              *ctx,
    uint8_t                     *buf,
    uint64_t                    length,
    mftah_fp__progress_hook_t    progress,
    void                        *progress_extra
);

/**
 * Encrypt a buffer. It must be a multiple of AES_BLOCKLEN.
 */
void
AES_CBC_encrypt_buffer(
    const mftah_registration_details_t *meta,
    struct AES_ctx              *ctx,
    uint8_t                     *buf,
    uint64_t                    length,
    mftah_fp__progress_hook_t    progress,
    void                        *progress_extra
);


#endif   /* LIBMFTAH_AES_H */
