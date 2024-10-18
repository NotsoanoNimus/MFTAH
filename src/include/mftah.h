/**
 * @file mftah.h
 * @brief Implementations for the default 'libmftah' protocol methods.
 *
 * @author Zack Puhl <zack@crows.dev>
 * @date 2024-10-17
 * 
 * @copyright Copyright (C) 2024 Zack Puhl
 * 
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, version 3.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see https://www.gnu.org/licenses/.
 */

#ifndef LIB_MFTAH_H
#define LIB_MFTAH_H

#include <stdint.h>
#include <stddef.h>



/* Syntactic definitions, really just to look similar to gnu-efi declarations. */
#define IN
#define OUT
#define OPTIONAL
#define CONST const
#define STATIC static
#define EXTERN extern
#define VOLATILE volatile

/* Define an immutable pointer and pointed value. */
typedef
CONST void *CONST
immutable_ref_t;


/* Default MFTAH compilation date. This is usually set during compilation by `make`. */
#ifndef MFTAH_RELEASE_DATE
#   define MFTAH_RELEASE_DATE 0x20241017
#endif


/* Used to track the status/condition of a payload or operation. */
#define MFTAH_SUCCESS                   0
#define MFTAH_FAIL_GENERIC              1
#define MFTAH_INVALID_PARAMETER         2
#define MFTAH_INVALID_ALIGNMENT         3
#define MFTAH_OUT_OF_RESOURCES          4
#define MFTAH_INVALID_SIGNATURE         5
#define MFTAH_BAD_PAYLOAD_STATE         10
#define MFTAH_PAYLOAD_NOT_DECRYPTED     11
#define MFTAH_INVALID_PASSWORD          12
#define MFTAH_INVALID_THREAD_COUNT      13
#define MFTAH_INVALID_ENCRYPTION_TYPE   14
#define MFTAH_INVALID_HMAC_TYPE         15
#define MFTAH_BAD_W_HMAC                20
#define MFTAH_BAD_O_HMAC                21
#define MFTAH_BAD_PAYLOAD_LEN           22
#define MFTAH_BAD_IV                    23
#define MFTAH_BAD_IV_SEEDS              24
#define MFTAH_BAD_PW_HASH               25
#define MFTAH_THREAD_BUSY               30

#define MFTAH_NOT_REGISTERED            MFTAH_SUCCESS

#define MFTAH_ERROR(x) \
    (MFTAH_SUCCESS != (x))


/* Wide-char strings vs. not, depending on predefined value. */
#ifdef MFTAH_WIDE_CHARS
#   define _w(x) L##x
#else
#   define _w(x) x
#endif


/* Semantic versioning in case we want it. */
#define LIBMFTAH_VERSION_MAJOR 1
#define LIBMFTAH_VERSION_MINOR 1
#define LIBMFTAH_VERSION_PATCH 3

#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)
#define LIBMFTAH_VERSION \
    _w(STRINGIFY(LIBMFTAH_VERSION_MAJOR) "." STRINGIFY(LIBMFTAH_VERSION_MINOR) "." STRINGIFY(LIBMFTAH_VERSION_PATCH))


/* Simple typedef to accommodate MFTAH statuses. */
typedef
uint8_t
mftah_status_t;


/* Misc other adjacent definitions that downstream projects might need. */
#define SIZE_OF_SHA_256_HASH    32
#define AES_BLOCKLEN            16
#define AES_KEYLEN              32


/* A set of log levels to be passed to registered printing functions. */
typedef
enum {
    MFTAH_LEVEL_ERROR       = 1,
    MFTAH_LEVEL_WARNING,
    MFTAH_LEVEL_NOTICE,
    MFTAH_LEVEL_INFO,
    MFTAH_LEVEL_DEBUG
} mftah_log_level_t;

/* Registration information associated with each MFTAH protocol instance. */
typedef
struct {
    void  (*printf)(mftah_log_level_t level, const char *restrict fmt, ...);
    void *(*malloc)(size_t size);
    void *(*calloc)(size_t count, size_t size);
    void *(*realloc)(void *at, size_t to_size);
    void *(*memcpy)(void *restrict dst, const void *restrict src, size_t length);
    void *(*memset)(void *at, int value, size_t length);
    void *(*memmove)(void *dst, const void *src, size_t length);
    int   (*memcmp)(const void *s1, const void *s2, size_t length);
    void  (*free)(void *ptr);
} mftah_registration_details_t;


/* A set of payload states. */
typedef
enum {
    INVALID     = 0,
    ENCRYPTED   = 1,
    DECRYPTED,
    UNKNOWN
} mftah_payload_state_t;


/* Work labels. Packages thread work order details into a public structure. */
/* NOTE: The types of supported encryption/HMACs can be adapted later in v2. */
typedef
enum {
    MFTAH_WORK_TYPE_ENCRYPT      = 1,
    MFTAH_WORK_TYPE_DECRYPT
} mftah_work_type_t;

typedef
enum {
    MFTAH_ENC_TYPE_AES256_CBC    = 1,
} mftah_encryption_type_t;

typedef
enum {
    MFTAH_HMAC_TYPE_SHA256       = 1,
} mftah_hmac_type_t;

typedef
enum {
    MFTAH_HASH_TYPE_SHA256      = 1,
} mftah_hash_type_t;


typedef
struct {
    uint8_t                 *location;
    size_t                  length;
    mftah_work_type_t       type;
    mftah_encryption_type_t enc_type;
    mftah_hmac_type_t       hmac_type;
    uint8_t                 thread_index;
    unsigned char           suppress_progress;
} mftah_work_order_t;



/****************************** */
/* Opaque struct definitions and typedefs. */

/**
 * The structure of a MFTAH payload header. 
 */
typedef
struct payload_header
{
    uint8_t     magic[8];                              /* 0-7 */
    uint8_t     version_info[4];                       /* 8-11 */
    uint8_t     encryption_type;                       /* 12 */
    uint8_t     hmac_type;                             /* 13 */
    uint8_t     password_hash_type;                    /* 14 */
    uint8_t     iv_seed_step;                          /* 15 */
    uint8_t     initialization_vector[AES_BLOCKLEN];   /* 16-31 */
    uint8_t     wrapper_hmac[SIZE_OF_SHA_256_HASH];    /* 32-63 */
    uint8_t     original_hmac[SIZE_OF_SHA_256_HASH];   /* 64-95 */
    uint64_t    payload_length;                        /* 96-103 */
    uint8_t     thread_count;                          /* 104 */
    uint8_t     iv_seeds[7];                           /* 105-111 */
    uint8_t     signature[AES_BLOCKLEN];               /* 112-127 */
} __attribute__((packed)) mftah_payload_header_t;

#define MFTAH_HEADER_ENCRYPT_OFFSET 96
#define MFTAH_HEADER_ENCRYPT_ADDL_SIZE \
    (sizeof(struct payload_header) - MFTAH_HEADER_ENCRYPT_OFFSET)

#define MFTAH_PAYLOAD_SIGNATURE     "_MFTAH_UNLOCKED_"
#define MFTAH_MAGIC                 "MFTAHFMT"

#define MFTAH_PAYLOAD_SIGNATURE_SIZE 16
#define MFTAH_MAGIC_SIGNATURE_SIZE 8

/* Global maximum thread count useable by MFTAH operations. */
#define MFTAH_MAX_THREAD_COUNT 64


/**
 * A meta-structure containing all MFTAH payload and crypto context details.
 */
typedef
struct payload
{
    uint8_t                 *buffer_base;       /* Loaded data base pointer */
    size_t                  actual_data_length; /* The original length of the loaded data */
    mftah_payload_state_t   state;              /* The current payload state (enc vs. dec) */
} __attribute__((packed)) mftah_payload_t;


/**
 * The primary abstract interface for MFTAH API operations that DOES NOT
 *  act as a series of loose, standalone functions.
 */
typedef
struct mftah_protocol
mftah_protocol_t;

typedef
CONST mftah_protocol_t *CONST
mftah_immutable_protocol_t;


/**
 * Used for hooking progress details during crypto operations.
 * 
 * TODO!
 */
typedef
void
(*mftah_fp__progress_hook_t)(
    IN CONST size_t     *current,
    IN CONST size_t     *out_of,
    IN OUT void         *extra
);

/**
 * TODO!
 */
typedef
struct {
    mftah_fp__progress_hook_t   hook;
    void                        *context;
} mftah_progress_t;


/**
 * TODO!
 */
typedef
mftah_status_t
(*mftah_fp__crypt_hook)(
    IN mftah_immutable_protocol_t   self,
    IN mftah_work_order_t           *work_order,
    IN immutable_ref_t              sha256_key,
    IN immutable_ref_t              iv,
    IN mftah_progress_t             *progress       OPTIONAL
);

/* Raw default crypto hook that is not modifiable externally. */
/* Most applications will want to use this--just indirectly--in protocol calls. */
EXTERN CONST mftah_fp__crypt_hook MFTAH_CRYPT_HOOK_DEFAULT;


/**
 * Used to await the end of all threads running. Once the current progress
 * passes the amount indicated by `queued_bytes`, the work is considered
 * completed.
 * 
 * @param[in]   queued_bytes    Amount of bytes for this spin to process (wash).
 */
typedef
void
(*mftah_fp__spin_callback)(
    IN size_t   *queued_bytes
);


/**
 * Used to write payload outputs to an output buffer. This is just an interface to
 * use with the 'yield_payload' protocol method. Unfortunately, this typing is a
 * necessity.
 * 
 * @param[in]   data        Data ready to be written to the output.
 * @param[in]   length      Length of the data segment.
 */
typedef
void
(*mftah_fp__yield_callback)(
    IN uint8_t  *data,
    IN size_t   length
);



/****************************** */
/****************************** */
/****************************** */
/* UEFI protocol-like definitions for encapsulating MFTAH oeprations. */

/**
 * Register a set of function hooks with the library for printing details.
 * 
 * @param[in]   self                    Handle to a MFTAH protocol instance.
 * @param[in]   registration_details    The function pointers and hooks used for printing.
 * 
 * @retval  MFTAH_SUCCESS            The operation completed successfully and information was printed.
 * @retval  MFTAH_INVALID_PARAMETER  The provided details pointer or `self` instance is NULL.
 */
typedef
mftah_status_t
(*mftah_fp__register_meta)(
    IN mftah_immutable_protocol_t                   self,
    IN CONST mftah_registration_details_t *CONST    registration_details
);

/**
 * Read in data at a buffer location and attempt to convert it to a
 * new caller-allocated MFTAH payload object. The library can determine
 * if the given payload is already in a MFTAH format by looking at both
 * (1) the "magic" value and (2) the payload Signature value.
 * 
 * @param[in]       self            A MFTAH protocol instance.
 * @param[in]       buffer          Pointer to the base of the input buffer to read.
 *                                   THE API CONSUMES AND FREES THIS POINTER.
 * @param[in]       buffer_length   The length of the input buffer.
 * @param[in,out]   new_payload     The caller-allocated payload base pointer.
 * @param[out]      new_payload_len The returned length of the encap. payload object.
 * 
 * @retval
 * TODO!
 */
typedef
mftah_status_t
(*mftah_fp__create_payload)(
    IN mftah_immutable_protocol_t   self,
    IN immutable_ref_t              buffer,
    IN size_t                       buffer_length,
    IN OUT mftah_payload_t          *new_payload,
    OUT size_t                      *new_payload_len    OPTIONAL
);

/**
 * Encrypt the target MFTAH payload with the given key. The key SHOULD NOT
 * already be in its hashed form.
 * 
 * @param[in]       self            A MFTAH protocol instance.
 * @param[in,out]   payload         The target payload to encrypt.
 * @param[in]       key             Base of the encryption key to use.
 * @param[in]       key_length      Length of the given encryption key.
 * @param[in]       thread_count    Amount of threads to run in parallel.
 * @param[in]       crypt_callback  Function to use for encrypting payloads.
 * @param[in]       spin_callback   Function to use while waiting to finish.
 * 
 * @retval
 * TODO!
 */
typedef
mftah_status_t
(*mftah_fp__encrypt_payload)(
    IN mftah_immutable_protocol_t   self,
    IN mftah_payload_t              *payload,
    IN immutable_ref_t              key,
    IN size_t                       key_length,
    IN uint8_t                      thread_count,
    IN mftah_fp__crypt_hook         crypt_callback,
    IN mftah_fp__spin_callback      spin_callback   OPTIONAL
);

/**
 * Quickly decrypt the signature field and confirm it matches the
 * expected value.
 * 
 * @param[in]   self            A MFTAH protocol instance.
 * @param[in]   payload         The target payload to validate against.
 * @param[in]   key             Base of the decryption key to try.
 * @param[in]   key_length      Length of the given decryption key.
 * @param[in]   crypt_callback  Function to use for decrypting the signature.
 * @param[in]   header_copy     Get back a copy of the decrypted header.
 */
typedef
mftah_status_t
(*mftah_fp__check_password)(
    IN mftah_immutable_protocol_t   self,
    IN mftah_payload_t              *payload,
    IN immutable_ref_t              key,
    IN size_t                       key_length,
    IN mftah_fp__crypt_hook         crypt_callback,
    OUT mftah_payload_header_t      **header_copy   OPTIONAL
);

/**
 * Decrypt the target MFTAH payload with the given key. The key SHOULD NOT
 * already be in its hashed form.
 * 
 * @param[in]       self            A MFTAH protocol instance.
 * @param[in,out]   payload         The target payload to decrypt.
 * @param[in]       key             Base of the decryption key to use.
 * @param[in]       key_length      Length of the given decryption key.
 * @param[in]       crypt_callback  Function to use for decrypting payloads.
 * @param[in]       spin_callback   Function to use while waiting to finish.
 * 
 * @retval
 * TODO!
 */
typedef
mftah_status_t
(*mftah_fp__decrypt_payload)(
    IN mftah_immutable_protocol_t   self,
    IN mftah_payload_t              *payload,
    IN immutable_ref_t              key,
    IN size_t                       key_length,
    IN mftah_fp__crypt_hook         crypt_callback,
    IN mftah_fp__spin_callback      spin_callback   OPTIONAL
);

/**
 * Decrypt the target MFTAH payload with the given key. The keys SHOULD NOT
 * already be in their hashed forms.
 * 
 * @param[in]       self                A MFTAH protocol instance.
 * @param[in,out]   payload             The target payload to rekey.
 * @param[in]       current_key         Base of the current key of the payload.
 * @param[in]       current_key_length  Length of the current key.
 * @param[in]       new_key             Base of the new key to use for the payload.
 * @param[in]       new_key_length      Length of the new key.
 * @param[in]       thread_count        Amount of threads to run in parallel.
 * @param[in]       decrypt_callback    Function to use for decrypting payloads.
 * @param[in]       encrypt_callback    Function to use for re-encrypting payloads.
 * @param[in]       spin_callback       Function to use while waiting to finish.
 * 
 * @retval
 * TODO!
 */
typedef
mftah_status_t
(*mftah_fp__rekey_payload)(
    IN mftah_immutable_protocol_t   self,
    IN mftah_payload_t              *payload,
    IN immutable_ref_t              current_key,
    IN size_t                       current_key_length,
    IN immutable_ref_t              new_key,
    IN size_t                       new_key_length,
    IN uint8_t                      thread_count,
    IN mftah_fp__crypt_hook         decrypt_callback,
    IN mftah_fp__crypt_hook         encrypt_callback,
    IN mftah_fp__spin_callback      spin_callback       OPTIONAL
);

/**
 * Calculate a SHA-256 hash over a certain set of input data. Returns
 * the hash in the `result` buffer, truncated to `result_length` bytes
 * or 32, whichever is smaller.
 * 
 * @param[in]       self            A MFTAH protocol instance.
 * @param[in]       input           A pointer to the input data to hash.
 * @param[in]       input_length    The size of the input data.
 * @param[out]      result          The start of the buffer where results are stored.
 * @param[in,out]   result_length   The length of the calculated hash to output into
 *                                   the `result` buffer, or 32, whichever is less.
 * 
 * @retval
 * TODO!
 */
typedef
mftah_status_t
(*mftah_fp__sha256_hash)(
    IN mftah_immutable_protocol_t   self,
    IN immutable_ref_t              input,
    IN CONST size_t                 input_length,
    OUT uint8_t                     *result,
    IN OUT uint8_t                  *result_length  OPTIONAL
);

/**
 * Calculate a SHA-256 HMAC over a certain set of input data. Returns
 * the HMAC in the `result` buffer, truncated to `result_length` bytes
 * or 32, whichever is smaller.
 * 
 * @param[in]       self            A MFTAH protocol instance.
 * @param[in]       input           A pointer to the input data to HMAC.
 * @param[in]       input_length    The size of the input data.
 * @param[in]       key             A pointer to the beginning of the unhashed key.
 * @param[in]       key_length      The length of the unhashed key.
 * @param[out]      result          The start of the buffer where results are stored.
 * @param[in,out]   result_length   The length of the calculated HMAC to output into
 *                                   the `result` buffer, or 32, whichever is less.
 * 
 * @retval
 * TODO!
 */
typedef
mftah_status_t
(*mftah_fp__sha256_hmac)(
    IN mftah_immutable_protocol_t   self,
    IN immutable_ref_t              input,
    IN CONST size_t                 input_length,
    IN immutable_ref_t              key,
    IN CONST size_t                 key_length,
    OUT uint8_t                     *result,
    IN OUT uint8_t                  *result_length  OPTIONAL
);

/**
 * Generate a series of random numbers into a destination buffer using an
 * internal pseudo-random number generator.
 * 
 * @param[in]       self            A MFTAH protocol instance.
 * @param[in]       minimum         An optional minimum boundary on generated values.
 * @param[in]       maximum         An optional maximum boundary on generated values.
 * @param[in]       count           How many bytes of random data to generate.
 * @param[out]      result          The start of the buffer where results are stored.
 * 
 * @retval  MFTAH_SUCCESS            The random data was generated and stored into `result`.
 * @retval  MFTAH_INVALID_PARAMETER  The min bound is greater than or equal to the max.
 * @retval  MFTAH_INVALID_PARAMETER  The `result` buffer is NULL.
 */
typedef
mftah_status_t
(*mftah_fp__get_random)(
    IN mftah_immutable_protocol_t   self,
    IN size_t                       minimum OPTIONAL,
    IN size_t                       maximum OPTIONAL,
    IN size_t                       count,
    OUT uint8_t                     *result
);

/**
 * The
 */
typedef
mftah_status_t
(*mftah_fp__get_decrypted_header)(
    IN mftah_immutable_protocol_t   self,
    IN mftah_payload_t              *payload,
    IN immutable_ref_t              key,
    IN size_t                       key_length,
    IN mftah_fp__crypt_hook         crypt_callback,
    OUT mftah_payload_header_t      **decrypted_copy
);

/**
 * Uses information about the payload to re-evaluate its state and refresh it.
 * This method also acts as a property for state information.
 * 
 * @param[in]   payload     The payload whose state should be checked and returned.
 * 
 * @retval  MFTAH_SUCCESS                    The operation completed successfully.
 * @retval  MFTAH_INVALID_PARAMETER          One of the parameters is NULL or invalid.
 */
typedef
mftah_status_t
(*mftah_fp__refresh_state)(
    IN mftah_immutable_protocol_t   self,
    IN mftah_payload_t              *payload
);

/**
 * Uses a passed function pointer to send the payload data to an output, based on
 * the current payload state (encrypted or decrypted).
 * 
 * @param[in]   payload                 The payload which should be sent through the output function.
 * @param[in]   requested_chunk_size    Size of each chunk to pass back into the callback function.
 * @param[in]   yield_callback          Called with each chunk of output data passed to it.
 * @param[in]   progress_hook           Progress reporting callback.
 * 
 * @retval  MFTAH_SUCCESS                    The operation completed successfully.
 * @retval  MFTAH_INVALID_PARAMETER          One of the parameters is NULL or invalid.
 */
typedef
mftah_status_t
(*mftah_fp__yield_payload)(
    IN mftah_immutable_protocol_t   self,
    IN mftah_payload_t              *payload,
    IN size_t                       requested_chunk_size,
    IN mftah_fp__yield_callback     yield_callback,
    IN mftah_fp__progress_hook_t    progress_hook           OPTIONAL
);


/**
 * The primary structure of a MFTAH protocol. This header file and library
 *  exports a single protocol instance with predefined concrete
 *  implementations as "MFTAH_PROTOCOL_INSTANCE" below.
 */
struct mftah_protocol
{
    mftah_fp__register_meta         register_hooks;
    mftah_fp__create_payload        create_payload;
    mftah_fp__encrypt_payload       encrypt;
    mftah_fp__check_password        check_password;
    mftah_fp__decrypt_payload       decrypt;
    mftah_fp__rekey_payload         rekey;
    mftah_fp__sha256_hash           create_hash;
    mftah_fp__sha256_hmac           create_hmac;
    mftah_fp__get_random            random;
    mftah_fp__get_decrypted_header  get_decrypted_header;
    mftah_fp__refresh_state         refresh_state;
    mftah_fp__yield_payload         yield_payload;

    mftah_registration_details_t     hooks;
};


/****************************** */
/* THE PRIMARY EXPORT OF THIS SCRIPT. */

/**
 * Populates a pointer structure with default MFTAH protocol functions.
 * The caller is responsible for allocating and freeing the new instance.
 * 
 * @param[in]   retval  The allocated MFTAH protocol structure to be populated.
 * 
 * @retval  MFTAH_SUCCESS            The operation completed successfully.
 * @retval  MFTAH_INVALID_PARAMETER  The input pointer for `retval` is NULL.
 */
mftah_status_t mftah_protocol_factory__create(
    mftah_protocol_t *retval
);



#endif   /* LIB_MFTAH_H */
