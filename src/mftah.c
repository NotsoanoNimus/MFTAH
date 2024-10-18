/**
 * @file mftah.c
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

#include "include/mftah.h"

#define MAX(x,y) \
    (((x) >= (y)) ? (x) : (y))
#define MIN(x,y) \
    (((x) <= (y)) ? (x) : (y))



#if LIBMFTAH_VERSION_MAJOR == 1


/* A bit cheap and unorthodox, but it doesn't really matter. We want a single module. */
#include "aes.c"
#include "sha256.c"
#include "prng.c"


#ifndef MFTAH_LIB_NOSTR
#define PRINT(level, x, ...) \
    if (self->hooks.printf) self->hooks.printf(level, _w(x), ##__VA_ARGS__);
#define PRINTLN(level, x, ...) \
    if (self->hooks.printf) { \
        self->hooks.printf(level, _w(x) _w("\n"), ##__VA_ARGS__); \
    }
#define MEMDUMP_LEVEL   MFTAH_LEVEL_DEBUG     /* Use this for testing memdump outside of debugging. */
#define MEMDUMP(ptr, len) \
    if (self->hooks.printf) { \
        self->hooks.printf(MEMDUMP_LEVEL, _w("[LIBMFTAH]  DEBUG:  MEMORY DUMP AT %p:\n"), ptr); \
        for (int i = 0; i < (len); ++i) { \
            self->hooks.printf(MEMDUMP_LEVEL, _w("%02x%c"), *((uint8_t *)(ptr)+i), !((i+1) % 16) ? _w('\n') : _w(' ')); \
        } \
        if ((len) % 16) self->hooks.printf(MEMDUMP_LEVEL, _w("\n")); \
    }
#define MEMDUMP_MSG(ptr, len, msg, ...) \
    if (self->hooks.printf) { \
        self->hooks.printf(MEMDUMP_LEVEL, _w(msg) _w("\n"), ##__VA_ARGS__); \
        MEMDUMP(ptr, len) \
    }
#else   /* MFTAH_LIB_NOSTR */
#define PRINT(level, x, ...)
#define PRINTLN(level, x, ...)
#define MEMDUMP(ptr, len)
#define MEMDUMP_MSG(ptr, len, msg, ...)
#endif   /* MFTAH_LIB_NOSTR */

const char *const MftahPayloadSignature  = MFTAH_PAYLOAD_SIGNATURE;
const char *const MftahMagic             = MFTAH_MAGIC;


/* These operations are so redundant that they should just be predefined. */
#define EXTRACT_HEADER(x) \
    mftah_payload_header_t *header = (mftah_payload_header_t *)(x);

#define PAYLOAD_BASE(header_pointer) \
    const void *payload_base \
        = (const void *)((uint8_t *)(header_pointer) + sizeof(struct payload_header));



/****************************** */
/****************************** */
/****************************** */
/* Functions and constants. */

static
mftah_status_t
mftah_crypt_default(IN mftah_immutable_protocol_t self,
                   IN mftah_work_order_t *work_order,
                   IN immutable_ref_t sha256_key,
                   IN immutable_ref_t iv,
                   IN mftah_progress_t *progress OPTIONAL)
{
    aes_ctx_t *aes_context = NULL;

    aes_context = (aes_ctx_t *)self->hooks.calloc(1, sizeof(aes_ctx_t));
    AES_init_ctx_iv(
        &(self->hooks),
        aes_context,
        (uint8_t *)sha256_key,
        (uint8_t *)iv
    );

    switch (work_order->type) {
        case MFTAH_WORK_TYPE_ENCRYPT:
            AES_CBC_encrypt_buffer(
                &(self->hooks),
                aes_context,
                work_order->location,
                work_order->length,
                progress ? progress->hook : NULL,
                progress ? progress->context : NULL
            );
            break;
        case MFTAH_WORK_TYPE_DECRYPT:
            AES_CBC_decrypt_buffer(
                &(self->hooks),
                aes_context,
                work_order->location,
                work_order->length,
                progress ? progress->hook : NULL,
                progress ? progress->context : NULL
            );
            break;
        default:
            return MFTAH_INVALID_PARAMETER;
    }

    self->hooks.free(aes_context);
    return MFTAH_SUCCESS;
}

const mftah_fp__crypt_hook MFTAH_CRYPT_HOOK_DEFAULT = mftah_crypt_default;


static
uint8_t *
mix_vectors(mftah_immutable_protocol_t self,
            mftah_payload_header_t *header,
            uint8_t threads)
{
    /* NOTE: This MUST be done because the same IV should NEVER be used with different, 
        non-sequential blocks of data. This effectively mixes IVs for each block with a
        random IV seed in an XOR chain from the previous one. */
    PRINTLN(MFTAH_LEVEL_DEBUG, "Mixing initialization vectors (%u : %u).", threads, header->iv_seed_step);
    uint8_t *mixed_vectors = self->hooks.calloc(1, (threads * sizeof(header->initialization_vector)));

    /* The first IV is equivalent to the "public" one used on the header. */
    self->hooks.memcpy(mixed_vectors,
                       header->initialization_vector,
                       sizeof(header->initialization_vector));
    MEMDUMP_MSG(mixed_vectors, sizeof(header->initialization_vector), "\nIV #0:");

    /* The rest of them sequentially mix with the previous vector. */
    /* NOTE: We only go up to 'threads-1' because the first IV is already set up (see above). */
    for (uint8_t t = 0; t < (threads - 1); ++t) {
        size_t iv_base_offset = (t + 1) * sizeof(header->initialization_vector);

        /* Only include the 'step' in the XOR if all seeds have already been used once. */
        uint8_t step = (threads >= sizeof(header->iv_seeds)) ? header->iv_seed_step : 0x00;

        /* The index of which seed to use depends on whether we've wrapped around once.
            And the value AT sizeof(seeds) is NOT included in this rotation. */
        uint8_t seed_position = t < sizeof(header->iv_seeds) ? t : (t % sizeof(header->iv_seeds));

        /* When the thread count has first passed the seeds available, use just the 'seed-step' to XOR the IV. */
        uint8_t seed = (threads == sizeof(header->iv_seeds)) ? 0x00 : (header->iv_seeds[seed_position]);

        PRINTLN(MFTAH_LEVEL_DEBUG, "MIX -- (%u : %u : %u)", (t + 1), step, seed_position);

        /* Now that we've got what we need, do the XOR. */
        for (size_t x = 0; x < sizeof(header->initialization_vector); ++x) {
            mixed_vectors[iv_base_offset + x]
                = (
                    mixed_vectors[(iv_base_offset + x) - sizeof(header->initialization_vector)]
                    ^ (step ^ seed)
                );
        }

        /* Dump it so it's visible during debugging. */
        MEMDUMP_MSG(((size_t)mixed_vectors + iv_base_offset), sizeof(header->initialization_vector), "IV #%u:", (t + 1));
    }

    return mixed_vectors;
}



/****************************** */
/****************************** */
/****************************** */
/* MFTAH protocol functions. */

static
mftah_status_t
mftah_register(IN mftah_immutable_protocol_t self,
               IN CONST mftah_registration_details_t *CONST registration_details)
{
    if (
        NULL == self
        || NULL == registration_details
    ) {
        return MFTAH_INVALID_PARAMETER;
    }

    registration_details->memcpy(
        (void *restrict)&(self->hooks),
        registration_details,
        sizeof(mftah_registration_details_t)
    );

    PRINTLN(MFTAH_LEVEL_DEBUG, "\n=== REGISTER call (completed) ===\n");

    return MFTAH_SUCCESS;
}


static
mftah_status_t
create(IN mftah_immutable_protocol_t self,
       IN immutable_ref_t buffer,
       IN uint64_t buffer_length,
       IN OUT mftah_payload_t *new_payload,
       OUT uint64_t *new_payload_len OPTIONAL)
{
    PRINTLN(MFTAH_LEVEL_DEBUG, "\n=== CREATE call ===\n");

    /* NOTE: This API call is not responsible for freeing any input pointers. */
    if (
        NULL == self
        || NULL == buffer
        || 0 == buffer_length
        || NULL == new_payload
    ) {
        return MFTAH_INVALID_PARAMETER;
    }

    /* Define the 'header' variable from the buffer. */
    EXTRACT_HEADER(buffer)

    /* If the first 8 bytes is equal to MAGIC, then this seems to be a payload, so convert it. */
    if (0 == self->hooks.memcmp(buffer, MftahMagic, sizeof(MftahMagic))) {
        PRINTLN(MFTAH_LEVEL_DEBUG, "Read valid and existing payload from input.");
        /* The existing payload size MUST always be equal to the AES block size. */
        /*   This is true even when the header stub is attached. */
        if (buffer_length % AES_BLOCKLEN) {
            PRINTLN(MFTAH_LEVEL_DEBUG, "Purported buffer length is not a multiple of %u: %llu", AES_BLOCKLEN, buffer_length);
            return MFTAH_INVALID_ALIGNMENT;
        }

        /* NOTE: The length here is rounded UP to the nearest 16-byte boundary. */
        /* During DECRYPT operations, the REAL length should always be read from the header. */
        new_payload->buffer_base = (uint8_t *)buffer;
        new_payload->actual_data_length = buffer_length - sizeof(struct payload_header);

        self->refresh_state(self, new_payload);
        return MFTAH_SUCCESS;
    }

    PRINTLN(MFTAH_LEVEL_DEBUG, "Read blob from input; creating new payload_header stub.");

    /* Scaffold the new payload meta and header. */
    new_payload->actual_data_length = buffer_length;

    /* Allocate the adjusted buffer and copy the provided payload. */
    PRINTLN(MFTAH_LEVEL_DEBUG, "Reallocating buffer with an extra %llu bytes.", sizeof(struct payload_header));
    new_payload->buffer_base
        = (uint8_t *)(self->hooks.realloc((uint8_t *)buffer, buffer_length + sizeof(struct payload_header)));
    if (NULL == new_payload->buffer_base) {
        return MFTAH_OUT_OF_RESOURCES;
    }

    self->hooks.memmove(new_payload->buffer_base + sizeof(struct payload_header), new_payload->buffer_base, buffer_length);
    self->hooks.memset(new_payload->buffer_base, 0x00, sizeof(struct payload_header));

    /* Reassign the header pointer to the new location. */
    header = (mftah_payload_header_t *)new_payload->buffer_base;

    /* Refresh the state of the payload and indicate the final length. */
    if (NULL != new_payload_len) {
        *new_payload_len = buffer_length + sizeof(struct payload_header);
    }

    /* Populate initial values for the header. */
    self->hooks.memcpy(header->magic, MftahMagic, MFTAH_MAGIC_SIGNATURE_SIZE);
    self->hooks.memcpy(header->signature, MftahPayloadSignature, MFTAH_PAYLOAD_SIGNATURE_SIZE);
    header->payload_length = buffer_length;

    self->refresh_state(self, new_payload);
    return MFTAH_SUCCESS;
}


static
mftah_status_t
encrypt(IN mftah_immutable_protocol_t self,
        IN mftah_payload_t *payload,
        IN immutable_ref_t key,
        IN uint64_t key_length,
        IN uint8_t thread_count,
        IN mftah_fp__crypt_hook crypt_callback,
        IN mftah_fp__spin_callback spin_callback OPTIONAL)
{
    mftah_status_t status = MFTAH_SUCCESS;
    mftah_work_order_t work_order = {0};
    uint8_t remainder = 0;
    uint8_t threads = MAX(1, thread_count);
    uint8_t password_hash[SIZE_OF_SHA_256_HASH] = {0};
    uint64_t total_crypt_size = 0;
    uint8_t hmac_len = SIZE_OF_SHA_256_HASH;

    PRINTLN(MFTAH_LEVEL_DEBUG, "\n=== ENCRYPT call ===\n");

    /* Defensive programming be like.. */
    if (
        NULL == self
        || NULL == payload
        || NULL == key || 0 == key_length
        || NULL == crypt_callback
    ) {
        return MFTAH_INVALID_PARAMETER;
    }

    if (threads > MFTAH_MAX_THREAD_COUNT) {
        return MFTAH_INVALID_THREAD_COUNT;
    }

    /* Make sure the payload is in the right state. */
    self->refresh_state(self, payload);
    if (DECRYPTED != payload->state) {
        return MFTAH_BAD_PAYLOAD_STATE;
    }

    PAYLOAD_BASE(payload->buffer_base)
    EXTRACT_HEADER(payload->buffer_base)

    /* Generate and store an HMAC over the original content to be encrypted. */
    PRINTLN(MFTAH_LEVEL_INFO, "Calculating O-HMAC.");
    PRINTLN(MFTAH_LEVEL_DEBUG, "Generating Original HMAC over (%llu) bytes.", payload->actual_data_length);
    status = self->create_hmac(self,
                               payload_base,
                               payload->actual_data_length,
                               key,
                               key_length,
                               header->original_hmac,
                               &hmac_len);
    if (MFTAH_ERROR(status)) {
        return status;
    } else if (SIZE_OF_SHA_256_HASH != hmac_len) {
        return MFTAH_BAD_O_HMAC;
    }
    MEMDUMP_MSG(header->original_hmac, SIZE_OF_SHA_256_HASH, "Generated O-HMAC:");

    /* If the input buffer is not an even block size, then make it so. */
    /* Since the payload header is a multiple of 16, we can ignore adding
        it when computing the remainder. */
    remainder = (payload->actual_data_length % AES_BLOCKLEN)
        ? (AES_BLOCKLEN - (payload->actual_data_length % AES_BLOCKLEN))
        : 0;
    if (remainder > 0) {
        uint8_t *new_buffer_base = (uint8_t *)self->hooks.realloc(
            payload->buffer_base,
            payload->actual_data_length + sizeof(struct payload_header) + remainder
        );
        if (NULL == new_buffer_base) {
            return MFTAH_OUT_OF_RESOURCES;
        }

        if (payload->buffer_base != new_buffer_base) {
            payload->buffer_base = new_buffer_base;

            payload_base = payload->buffer_base + sizeof(struct payload_header);
            header = (mftah_payload_header_t *)payload->buffer_base;
        }
        
        /* Pad the ending with 0xFF values and update the stored actual data length. */
        self->hooks.memset((void *)(payload_base + payload->actual_data_length), 0xFF, remainder);

        payload->actual_data_length += remainder;
    }

    /* Hash the given password. */
    PRINTLN(MFTAH_LEVEL_DEBUG, "Hashing the provided password.");
    status = self->create_hash(self,
                               key,
                               key_length,
                               password_hash,
                               NULL);
    if (MFTAH_ERROR(status)) {
        return MFTAH_BAD_PW_HASH;
    }

    /* Randomize the IV. */
    PRINTLN(MFTAH_LEVEL_DEBUG, "Creating a new initialization vector.");
    status = self->random(self,
                          0,
                          0,
                          sizeof(header->initialization_vector),
                          header->initialization_vector);
    if (MFTAH_ERROR(status)) {
        return MFTAH_BAD_IV;
    }

    /* Randomize the seven possible IV mixer seeds. */
    PRINTLN(MFTAH_LEVEL_DEBUG, "Creating the initialization vector seeds.");
    status = self->random(self,
                          0,
                          0,
                          sizeof(header->iv_seeds),
                          header->iv_seeds);
    if (MFTAH_ERROR(status)) {
        return MFTAH_BAD_IV_SEEDS;
    }

    /* Randomize the IV step value. This CANNOT be zero. */
    PRINTLN(MFTAH_LEVEL_DEBUG, "Initializing the IV step value.");
    do {
        status = self->random(self,
                              0,
                              0,
                              sizeof(header->iv_seed_step),
                              &(header->iv_seed_step));
    } while (0 == header->iv_seed_step);

    MEMDUMP_MSG(password_hash, SIZE_OF_SHA_256_HASH, "Got loaded password hash:");
    MEMDUMP_MSG(header->initialization_vector, sizeof(header->initialization_vector), "Using first IV:");
    MEMDUMP_MSG(header->signature, MFTAH_PAYLOAD_SIGNATURE_SIZE, "Original Signature:");
    MEMDUMP_MSG(header->iv_seeds, sizeof(header->iv_seeds), "IV Seeds:"); PRINT(MFTAH_LEVEL_DEBUG, "\n");
    MEMDUMP_MSG(&(header->iv_seed_step), sizeof(header->iv_seed_step), "Seed step value:"); PRINT(MFTAH_LEVEL_DEBUG, "\n");

    PRINTLN(MFTAH_LEVEL_DEBUG, "Populating other header details.");
    header->thread_count = threads;

#if LIBMFTAH_VERSION_MAJOR == 1
    /* Version 1 of the format _always_ uses these algorithms. */
    header->encryption_type = MFTAH_ENC_TYPE_AES256_CBC;
    header->hmac_type = MFTAH_HMAC_TYPE_SHA256;
    header->password_hash_type = MFTAH_HASH_TYPE_SHA256;
#endif   /* LIBMFTAH_VERSION_MAJOR == 1 */

    /* Forcibly reinforce that the signature is present. */
    PRINTLN(MFTAH_LEVEL_DEBUG, "Copying signature.");
    self->hooks.memcpy(header->signature, MftahPayloadSignature, MFTAH_PAYLOAD_SIGNATURE_SIZE);

    /* Set the version indication. */
    PRINTLN(MFTAH_LEVEL_DEBUG, "Setting version details.");
    header->version_info[0] = LIBMFTAH_VERSION_MAJOR;
    header->version_info[1] = LIBMFTAH_VERSION_MINOR;
    header->version_info[2] = LIBMFTAH_VERSION_PATCH;

    uint8_t *mixed_vectors = mix_vectors(self, header, threads);

    /* Encrypt the 3 blocks of the header as their own separate process. This will guarantee
       the same division of work is present on the decrypting end. */
    PRINTLN(MFTAH_LEVEL_DEBUG, "Encrypting payload header.");
    work_order.location = payload->buffer_base + MFTAH_HEADER_ENCRYPT_OFFSET;
    work_order.length = MFTAH_HEADER_ENCRYPT_ADDL_SIZE;
    work_order.thread_index = 0;
    work_order.type = MFTAH_WORK_TYPE_ENCRYPT;
    work_order.suppress_progress = 1;

    crypt_callback(self,
                   &work_order,
                   (immutable_ref_t)password_hash,
                   (immutable_ref_t)header->initialization_vector,
                   NULL);
    if (NULL != spin_callback) {
        uint64_t addl_size = MFTAH_HEADER_ENCRYPT_ADDL_SIZE;
        spin_callback(&addl_size);
    }

    /* Encrypt the content. Reaches into the callback provided by the caller to manage threads externally. */
    PRINTLN(MFTAH_LEVEL_DEBUG, "Calculating work divisions.");
    total_crypt_size = payload->actual_data_length;

    uint64_t chunk_size = (total_crypt_size / threads) - ((total_crypt_size / threads) % AES_BLOCKLEN);
    uint64_t last_chunk_size = total_crypt_size - ((thread_count - 1) * chunk_size);

    PRINTLN(MFTAH_LEVEL_DEBUG, "Calculated operation chunk sizes (%llu : %llu).", chunk_size, last_chunk_size);

    if (threads > 1) {
        PRINTLN(MFTAH_LEVEL_INFO, "Threading the encryption callback.");
    } else {
        PRINTLN(MFTAH_LEVEL_INFO, "Invoking the encryption callback.");
    }

    PRINTLN(MFTAH_LEVEL_DEBUG, "Preparing encryption threads.");
    for (uint8_t t = 0; t < threads; ++t) {
        PRINTLN(MFTAH_LEVEL_DEBUG, "Forming work order for thread (%u).", t);
        work_order.location = (uint8_t *)(payload_base + (t * chunk_size));
        work_order.length = ((threads - 1) == t) ? last_chunk_size : chunk_size;
        work_order.type = MFTAH_WORK_TYPE_ENCRYPT;
        work_order.thread_index = t;
        work_order.suppress_progress = 0;

        crypt_callback(self,
                       &work_order,
                       (immutable_ref_t)password_hash,
                       (immutable_ref_t)&(mixed_vectors[t * sizeof(header->initialization_vector)]),
                       NULL);
    }

    if (NULL != spin_callback) {
        /* Wait for threads to finish. */
        spin_callback(&total_crypt_size);
    }

    /* Don't hang onto these values anymore. */
    self->hooks.free(mixed_vectors);

    /* Finally, generate the wrapper HMAC over the encrypted content. */
    PRINTLN(MFTAH_LEVEL_INFO, "Calculating W-HMAC.");
    PRINTLN(MFTAH_LEVEL_DEBUG, "Generating Wrapper HMAC over (%llu) bytes.", total_crypt_size);
    status = self->create_hmac(self,
                               payload->buffer_base + MFTAH_HEADER_ENCRYPT_OFFSET,
                               total_crypt_size + MFTAH_HEADER_ENCRYPT_ADDL_SIZE,
                               key,
                               key_length,
                               header->wrapper_hmac,
                               &hmac_len);
    if (MFTAH_ERROR(status)) {
        return status;
    } else if (SIZE_OF_SHA_256_HASH != hmac_len) {
        return MFTAH_BAD_W_HMAC;
    }
    MEMDUMP_MSG(header->wrapper_hmac, SIZE_OF_SHA_256_HASH, "Generated W-HMAC:");

    self->refresh_state(self, payload);
    return MFTAH_SUCCESS;
}


static
mftah_status_t
get_decrypted_header(IN mftah_immutable_protocol_t self,
                     IN mftah_payload_t *payload,
                     IN immutable_ref_t key,
                     IN uint64_t key_length,
                     IN mftah_fp__crypt_hook crypt_callback,
                     OUT mftah_payload_header_t **decrypted_copy)
{
    mftah_status_t status = MFTAH_SUCCESS;
    mftah_payload_header_t *header_copy =
        (mftah_payload_header_t *)self->hooks.calloc(1, sizeof(struct payload_header));
    uint8_t encrypted_region_length = sizeof(struct payload_header) - MFTAH_HEADER_ENCRYPT_OFFSET;
    mftah_work_order_t new_order = {0};
    uint8_t password_hash[SIZE_OF_SHA_256_HASH] = {0};

    PRINTLN(MFTAH_LEVEL_DEBUG, "\n=== GET DECRYPTED HEADER call ===\n");

    if (
        NULL == self
        || NULL == payload
        || NULL == key || 0 == key_length
        || NULL == crypt_callback
        || NULL == decrypted_copy
    ) {
        self->hooks.free(header_copy);
        return MFTAH_INVALID_PARAMETER;
    }

    EXTRACT_HEADER(payload->buffer_base)
    self->hooks.memcpy(header_copy, header, sizeof(struct payload_header));

    self->refresh_state(self, payload);
    if (DECRYPTED == payload->state) {
        PRINTLN(MFTAH_LEVEL_DEBUG, "The payload is already decrypted. Returning header copy.");

        *decrypted_copy = header_copy;
        return MFTAH_SUCCESS;
    }

    /* Hash the given password. */
    PRINTLN(MFTAH_LEVEL_DEBUG, "Creating password hash.");
    status = self->create_hash(self,
                               key,
                               key_length,
                               password_hash,
                               NULL);
    if (MFTAH_ERROR(status)) {
        self->hooks.free(header_copy);
        return MFTAH_BAD_PW_HASH;
    }

    PRINTLN(MFTAH_LEVEL_DEBUG, "Forming header decryption work order.");
    new_order.location = (uint8_t *)&(header_copy->payload_length);
    new_order.length = encrypted_region_length;
    new_order.thread_index = 0;
    new_order.type = MFTAH_WORK_TYPE_DECRYPT;
    new_order.suppress_progress = 1;

    status = crypt_callback(self,
                            &new_order,
                            password_hash,
                            header->initialization_vector,
                            NULL);
    if (MFTAH_ERROR(status)) {
        self->hooks.free(header_copy);
        return status;
    }

    PRINTLN(MFTAH_LEVEL_DEBUG, "Decrypted header.");
    MEMDUMP(header_copy, sizeof(struct payload_header));

    PRINTLN(MFTAH_LEVEL_DEBUG, "All done. Storing pointer to decrypted copy.");
    *decrypted_copy = header_copy;

    return MFTAH_SUCCESS;
}


static
mftah_status_t
check_password(IN mftah_immutable_protocol_t self,
               IN mftah_payload_t *payload,
               IN immutable_ref_t key,
               IN uint64_t key_length,
               IN mftah_fp__crypt_hook crypt_callback,
               OUT mftah_payload_header_t **header_copy OPTIONAL)
{
    mftah_status_t status = MFTAH_SUCCESS;
    mftah_payload_header_t *decrypted_header = NULL;

    PRINTLN(MFTAH_LEVEL_DEBUG, "\n=== CHECK PASSWORD call ===\n");

    if (
        NULL == self
        || NULL == payload
        || NULL == key
        || 0 == key_length
        || NULL == crypt_callback
    ) {
        return MFTAH_INVALID_PARAMETER;
    }

    status = self->get_decrypted_header(self,
                                        payload,
                                        key,
                                        key_length,
                                        crypt_callback,
                                        &decrypted_header);
    if (MFTAH_ERROR(status)) {
        self->hooks.free(decrypted_header);
        return MFTAH_BAD_PW_HASH;
    }

    if (0 != self->hooks.memcmp(decrypted_header->signature,
                                MftahPayloadSignature,
                                MFTAH_PAYLOAD_SIGNATURE_SIZE)
    ) {
        self->hooks.free(decrypted_header);
        return MFTAH_INVALID_PASSWORD;
    }

    if (NULL != header_copy) {
        *header_copy = decrypted_header;
    } else {
        self->hooks.free(decrypted_header);
    }

    return MFTAH_SUCCESS;
}


static
mftah_status_t
decrypt(IN mftah_immutable_protocol_t self,
        IN mftah_payload_t *payload,
        IN immutable_ref_t key,
        IN uint64_t key_length,
        IN mftah_fp__crypt_hook crypt_callback,
        IN mftah_fp__spin_callback spin_callback OPTIONAL)
{
    mftah_status_t status = MFTAH_SUCCESS;

    mftah_work_order_t work_order = {0};

    uint8_t remainder = 0;
    uint64_t total_crypt_size = 0;

    uint8_t password_hash[SIZE_OF_SHA_256_HASH] = {0};
    uint8_t wrapper_hmac[SIZE_OF_SHA_256_HASH] = {0};

    uint8_t original_hmac[SIZE_OF_SHA_256_HASH] = {0};
    uint8_t hmac_len = SIZE_OF_SHA_256_HASH;

    uint64_t stored_length = 0;
    uint8_t threads = 0;

    PRINTLN(MFTAH_LEVEL_DEBUG, "\n=== DECRYPT call ===\n");

    if (
        NULL == self
        || NULL == payload
        || NULL == key || 0 == key_length
        || NULL == crypt_callback
    ) {
        return MFTAH_INVALID_PARAMETER;
    }

    /* Make sure the payload is in the right state. */
    self->refresh_state(self, payload);
    if (ENCRYPTED != payload->state) {
        return MFTAH_BAD_PAYLOAD_STATE;
    }

    PAYLOAD_BASE(payload->buffer_base)
    EXTRACT_HEADER(payload->buffer_base)

    /* Get the length stored in the file header by checking the password too. */
    status = self->check_password(self,
                                  payload,
                                  key,
                                  key_length,
                                  /* WARNING: THIS CANNOT BE THE crypt_callback WITHOUT SOME KIND OF spin_callback BECAUSE:
                                    any non-blocking/threaded operations cause the program to proceed without waiting for
                                    the header to decrypt. This results in a race condition where sometimes the password
                                    is valid and sometimes it's not! */
                                  /* I wasted over 3 hours determining that this was the cause of a debug/non-debug race condition. */
                                  /* Adding a `spin_callback` here is going to make this even more gnarled and unwieldly.
                                        Not doing it right now. */
                                  MFTAH_CRYPT_HOOK_DEFAULT,
                                  &header);
    if (MFTAH_ERROR(status)) {
        return status;
    }

    /* Extract interesting initial values and evaluate them. */
    stored_length = header->payload_length;

    threads = MAX(1, header->thread_count);
    if (threads > MFTAH_MAX_THREAD_COUNT) {
        return MFTAH_INVALID_THREAD_COUNT;
    }

    PRINTLN(
        MFTAH_LEVEL_DEBUG,
        "Got original length (%llu), IV step (%u), and thread count (%d).",
        stored_length,
        header->iv_seed_step,
        threads
    );
    payload->actual_data_length = stored_length;

    /* Hash the given password. */
    PRINTLN(MFTAH_LEVEL_DEBUG, "Hashing the provided password.");
    status = self->create_hash(self,
                               key,
                               key_length,
                               password_hash,
                               NULL);
    if (MFTAH_ERROR(status)) {
        return MFTAH_BAD_PW_HASH;
    }

    remainder = (stored_length % AES_BLOCKLEN)
        ? (AES_BLOCKLEN - (stored_length % AES_BLOCKLEN))
        : 0;
    total_crypt_size = stored_length + remainder;

    /* Reproduce the wrapper HMAC over the encrypted content and verify that it matches. */
    PRINTLN(MFTAH_LEVEL_INFO, "Calculating W-HMAC.");
    PRINTLN(MFTAH_LEVEL_DEBUG, "Calculating Wrapper HMAC over (%llu) bytes.", total_crypt_size);
    status = self->create_hmac(self,
                               payload->buffer_base + MFTAH_HEADER_ENCRYPT_OFFSET,
                               total_crypt_size + MFTAH_HEADER_ENCRYPT_ADDL_SIZE,
                               key,
                               key_length,
                               wrapper_hmac,
                               &hmac_len);
    if (MFTAH_ERROR(status)) {
        return status;
    }

    MEMDUMP_MSG(wrapper_hmac, SIZE_OF_SHA_256_HASH, "Calculated W-HMAC:");
    MEMDUMP_MSG(header->wrapper_hmac, SIZE_OF_SHA_256_HASH, "Current W-HMAC:");

    if (
        SIZE_OF_SHA_256_HASH != hmac_len
        || 0 != self->hooks.memcmp(wrapper_hmac, header->wrapper_hmac, SIZE_OF_SHA_256_HASH)
    ) {
        return MFTAH_BAD_W_HMAC;
    }

    /* This is annoying, but since 'header' is a new allocation, memcpy it back to the payload. */
    /*   NOTE: This is necessary for rekeying when the payload state is checked for the signature. */
    /*   ADDL. NOTE: This MUST be done after the W-HMAC calculation since that's done with the encrypted header. */
    self->hooks.memcpy(payload->buffer_base, header, sizeof(mftah_payload_header_t));
    self->hooks.free(header);
    header = (mftah_payload_header_t *)payload->buffer_base;

    PRINTLN(MFTAH_LEVEL_DEBUG, "Calculating work divisions.");
    uint64_t chunk_size = (total_crypt_size / threads) - ((total_crypt_size / threads) % AES_BLOCKLEN);
    uint64_t last_chunk_size = total_crypt_size - ((threads - 1) * chunk_size);

    PRINTLN(MFTAH_LEVEL_DEBUG, "Calculated operation chunk sizes (%llu : %llu).", chunk_size, last_chunk_size);

    if (threads > 1) {
        PRINTLN(MFTAH_LEVEL_INFO, "Threading the decryption callback.");
    } else {
        PRINTLN(MFTAH_LEVEL_INFO, "Invoking the decryption callback.");
    }

    /* Form the initialization vector chain; same way we do in 'encrypt'. */
    uint8_t *mixed_vectors = mix_vectors(self, header, threads);

    PRINTLN(MFTAH_LEVEL_DEBUG, "Preparing decryption threads.");
    for (uint8_t t = 0; t < threads; ++t) {
        PRINTLN(MFTAH_LEVEL_DEBUG, "Forming work order for thread (%u).", t);
        work_order.location = (uint8_t *)(payload_base + (t * chunk_size));
        work_order.length = ((threads - 1) == t) ? last_chunk_size : chunk_size;
        work_order.type = MFTAH_WORK_TYPE_DECRYPT;
        work_order.thread_index = t;
        work_order.suppress_progress = 0;

        crypt_callback(self,
                       &work_order,
                       (immutable_ref_t)password_hash,
                       (immutable_ref_t)&(mixed_vectors[t * sizeof(header->initialization_vector)]),
                       NULL);
    }

    if (NULL != spin_callback) {
        /* Wait for the threads to finish. */
        spin_callback(&total_crypt_size);
    }

    /* Finally, no need for this anymore. */
    self->hooks.free(mixed_vectors);

    PRINTLN(MFTAH_LEVEL_DEBUG, "Purported payload length: %llu", header->payload_length);
    PRINTLN(MFTAH_LEVEL_DEBUG, "Input buffer length: %llu", payload->actual_data_length);

    /* Sanity check: our expected signature should now exist. */
    if (0 != self->hooks.memcmp(header->signature, MftahPayloadSignature, MFTAH_PAYLOAD_SIGNATURE_SIZE)) {
        return MFTAH_INVALID_SIGNATURE;
    }

    /* Reproduce the HMAC over the original content that was encrypted. */
    PRINTLN(MFTAH_LEVEL_INFO, "Calculating O-HMAC.");
    PRINTLN(MFTAH_LEVEL_DEBUG, "Calculating Original HMAC over (%llu) bytes.", header->payload_length);
    status = self->create_hmac(self,
                               payload_base,
                               header->payload_length,
                               key,
                               key_length,
                               original_hmac,
                               &hmac_len);
    if (MFTAH_ERROR(status)) {
        return status;
    }

    MEMDUMP_MSG(original_hmac, SIZE_OF_SHA_256_HASH, "Calculated O-HMAC:");
    MEMDUMP_MSG(header->original_hmac, SIZE_OF_SHA_256_HASH, "Current O-HMAC:");
    if (
        SIZE_OF_SHA_256_HASH != hmac_len
        || 0 != self->hooks.memcmp(original_hmac, header->original_hmac, SIZE_OF_SHA_256_HASH)
    ) {
        return MFTAH_BAD_O_HMAC;
    }

    self->refresh_state(self, payload);
    return MFTAH_SUCCESS;
}


static
mftah_status_t
rekey(IN mftah_immutable_protocol_t self,
      IN mftah_payload_t *payload,
      IN immutable_ref_t current_key,
      IN uint64_t current_key_length,
      IN immutable_ref_t new_key,
      IN uint64_t new_key_length,
      IN uint8_t thread_count,
      IN mftah_fp__crypt_hook decrypt_callback,
      IN mftah_fp__crypt_hook encrypt_callback,
      IN mftah_fp__spin_callback spin_callback OPTIONAL)
{
    mftah_status_t status = MFTAH_SUCCESS;

    PRINTLN(MFTAH_LEVEL_DEBUG, "\n=== REKEY call ===\n");

    if (
        NULL == self
        || NULL == payload
        || NULL == current_key
        || 0 == current_key_length
        || NULL == new_key
        || 0 == new_key_length
        || NULL == decrypt_callback
        || NULL == encrypt_callback
    ) {
        return MFTAH_INVALID_PARAMETER;
    }

    /* Rekeying must be done on an encrypted payload ONLY. */
    self->refresh_state(self, payload);
    if (ENCRYPTED != payload->state) {
        return MFTAH_BAD_PAYLOAD_STATE;
    }

    /* If the key isn't changing, there's no point in rekeying. */
    MEMDUMP_MSG(current_key, current_key_length, "CURRENT KEY:");
    MEMDUMP_MSG(new_key, new_key_length, "NEW KEY:");
    if (
        0 == self->hooks.memcmp(current_key, new_key, MIN(current_key_length, new_key_length))
        && current_key_length == new_key_length   /* the keys must be the same length to be the exact same */
    ) {
        PRINTLN(MFTAH_LEVEL_DEBUG, "Current and new passwords are the same. Not re-keying.");
        return MFTAH_SUCCESS;
    }

    PRINTLN(MFTAH_LEVEL_INFO, "REKEY - Running initial decryption.");
    status = self->decrypt(self,
                           payload,
                           current_key,
                           current_key_length,
                           decrypt_callback,
                           spin_callback);
    if (MFTAH_ERROR(status)) {
        return status;
    }

    PRINTLN(MFTAH_LEVEL_INFO, "REKEY - Encrypting with the updated password.");
    status = self->encrypt(self,
                           payload,
                           new_key,
                           new_key_length,
                           thread_count,
                           encrypt_callback,
                           spin_callback);
    if (MFTAH_ERROR(status)) {
        return status;
    }

    return MFTAH_SUCCESS;
}


static
mftah_status_t
hash(IN mftah_immutable_protocol_t self,
     IN immutable_ref_t input,
     IN CONST uint64_t input_length,
     OUT uint8_t *result,
     IN OUT uint8_t *result_length OPTIONAL)
{
    uint8_t length = 0;
    uint8_t intermediate_result[SIZE_OF_SHA_256_HASH] = {0};

    PRINTLN(MFTAH_LEVEL_DEBUG, "\n=== CREATE HASH call ===\n");

    if (
        NULL == self
        || NULL == input || 0 == input_length
        || NULL == result
        || (NULL != result_length && 0 == *result_length)
    ) {
        return MFTAH_INVALID_PARAMETER;
    }

    length = (NULL != result_length)
        ? MIN(SIZE_OF_SHA_256_HASH, *result_length)
        : SIZE_OF_SHA_256_HASH;

    calc_sha_256(self,
                 intermediate_result,
                 input,
                 input_length);

    self->hooks.memcpy(result, intermediate_result, length);

    if (NULL != result_length) {
        *result_length = length;
    }

    return MFTAH_SUCCESS;
}


static
mftah_status_t
hmac(IN mftah_immutable_protocol_t self,
     IN immutable_ref_t input,
     IN CONST uint64_t input_length,
     IN immutable_ref_t key,
     IN CONST uint64_t key_length,
     OUT uint8_t *result,
     IN OUT uint8_t *result_length OPTIONAL)
{
    uint8_t length = 0;
    uint8_t intermediate_result[SIZE_OF_SHA_256_HASH] = {0};

    PRINTLN(MFTAH_LEVEL_DEBUG, "\n=== CREATE HMAC call ===\n");

    if (
        NULL == self
        || NULL == input || 0 == input_length
        || NULL == key || 0 == key_length
        || NULL == result
        || (NULL != result_length && 0 == *result_length)
    ) {
        return MFTAH_INVALID_PARAMETER;
    }

    hmac_sha256(self,
                key,
                key_length,
                input,
                input_length,
                intermediate_result);

    length = (NULL != result_length)
        ? MIN(SIZE_OF_SHA_256_HASH, *result_length)
        : SIZE_OF_SHA_256_HASH;

    self->hooks.memcpy(result, intermediate_result, length);

    if (NULL != result_length) {
        *result_length = length;
    }

    return MFTAH_SUCCESS;
}


static
mftah_status_t
mftahrand(IN mftah_immutable_protocol_t self,
          IN uint64_t minimum OPTIONAL,
          IN uint64_t maximum OPTIONAL,
          IN uint64_t count,
          OUT uint8_t *result)
{
    uint64_t *rand = NULL;
    uint64_t len = count;
    uint8_t chunk_size = 0;
    uint8_t *scroll = result;

    PRINTLN(MFTAH_LEVEL_DEBUG, "\n=== RANDOM call ===\n");

    if (0 == count) {
        return MFTAH_SUCCESS;
    }

    if ((minimum | maximum) && minimum >= maximum) {
        return MFTAH_INVALID_PARAMETER;
    }

    /* Initialize the PRNG. */
    prng_init(self);

    rand = (uint64_t *)self->hooks.malloc(sizeof(uint64_t));

    while (scroll < (result + count)) {
        chunk_size = MIN(len, sizeof(uint64_t));

        *rand = (minimum | maximum)
            ? prng_next_bounded(minimum, maximum)
            : prng_next();
        
        self->hooks.memcpy(scroll, rand, chunk_size);

        len -= chunk_size;
        scroll += chunk_size;
    }

    self->hooks.free(rand);

    return MFTAH_SUCCESS;
}


static
mftah_status_t
refresh_state(IN mftah_immutable_protocol_t self,
              IN mftah_payload_t *payload)
{
    PRINTLN(MFTAH_LEVEL_DEBUG, "\n=== REFRESH STATE call ===\n");

    if (NULL == payload) {
        return MFTAH_INVALID_PARAMETER;
    }

    EXTRACT_HEADER(payload->buffer_base)

    MEMDUMP(header, sizeof(struct payload_header));

    /* If the magic value isn't found, this payload's buffer is nonsense or unsafe. */
    if (0 != self->hooks.memcmp((void *)header, (void *)MftahMagic, sizeof(MftahMagic))) {
        PRINTLN(MFTAH_LEVEL_WARNING, "Payload data is missing the MAGIC value. This shouldn't happen.\n");
        payload->state = INVALID;
        return MFTAH_BAD_PAYLOAD_STATE;
    }

    /* When the Signature field doesn't match, assume the payload is currently encrypted. */
    else if (0 != self->hooks.memcmp(
        (const void *)(header->signature),
        (const void *)MftahPayloadSignature,
        sizeof(MftahPayloadSignature)
    )) {
        PRINTLN(MFTAH_LEVEL_DEBUG, "State: Encrypted\n");
        payload->state = ENCRYPTED;
    }

    /* Otherwise, the payload should be in the decrypted state. */
    else {
        PRINTLN(MFTAH_LEVEL_DEBUG, "State: Decrypted\n");
        payload->state = DECRYPTED;
    }

    return MFTAH_SUCCESS;
}


static
mftah_status_t
yield(IN mftah_immutable_protocol_t self,
      IN mftah_payload_t *payload,
      IN uint64_t requested_chunk_size,
      IN mftah_fp__yield_callback yield_callback,
      IN mftah_fp__progress_hook_t progress_hook OPTIONAL)
{
    mftah_status_t status = MFTAH_SUCCESS;
    uint64_t buffer_length = 0;
    uint64_t write_size = 0;
    uint64_t total = 0;
    uint8_t *scroll = NULL;

    PRINTLN(MFTAH_LEVEL_DEBUG, "\n=== YIELD call ===\n");

    if (
        NULL == payload
        || NULL == yield_callback
        || 0 == requested_chunk_size
    ) {
        return MFTAH_INVALID_PARAMETER;
    }

    EXTRACT_HEADER(payload->buffer_base);

    status = self->refresh_state(self, payload);
    if (MFTAH_ERROR(status)) {
        return status;
    }

    buffer_length = (DECRYPTED == payload->state)
        ? header->payload_length
        : payload->actual_data_length;

    scroll = payload->buffer_base;

    if (NULL == scroll || 0 == buffer_length) {
        PRINTLN(MFTAH_LEVEL_WARNING, "Yield operation returned a bad buffer length or scroll pointer.");
        return MFTAH_BAD_PAYLOAD_LEN;
    } else if (ENCRYPTED == payload->state && 0 != (buffer_length % AES_BLOCKLEN)) {
        PRINTLN(MFTAH_LEVEL_WARNING, "Yield operation returned a misaligned buffer length.");
        return MFTAH_BAD_PAYLOAD_LEN;
    }

    if (DECRYPTED == payload->state) {
        /* Do not output/yield the payload header when the payload is in the DECRYPTED state. */
        PRINTLN(MFTAH_LEVEL_DEBUG,
                "Adjusting the scroll pointer forward by %lu bytes.",
                sizeof(mftah_payload_header_t));

        scroll += sizeof(mftah_payload_header_t);
    } else {
        /* Otherwise, the BUFFER LENGTH should also account for the payload's header. */
        buffer_length += sizeof(mftah_payload_header_t);
    }

    PRINTLN(MFTAH_LEVEL_DEBUG, "Tentative output size of (%lu) bytes.", buffer_length);
    PRINTLN(MFTAH_LEVEL_DEBUG, "Tentative scroll starting position at (%p).", scroll);

    do {
        /* Be careful to write only the actual data remainder and not a
            full block at the end of the buffer. */
        write_size = 
            ((total + requested_chunk_size) > buffer_length)
                ? (buffer_length - total)
                : requested_chunk_size;

        yield_callback(scroll, write_size);

        if (progress_hook && !(total % (1 << 22))) {
            progress_hook(&total, &buffer_length, NULL);
        }

        scroll += write_size;
        total += write_size;
    } while (total < buffer_length && write_size > 0);

    if (progress_hook) {
        progress_hook(&buffer_length, &buffer_length, NULL);
    }

    return MFTAH_SUCCESS;
}



/****************************** */
/****************************** */
/****************************** */
/* Primary concrete module export. */
mftah_status_t
mftah_protocol_factory__create(mftah_protocol_t *retval)
{
    retval->register_hooks          = mftah_register;
    retval->create_payload          = create;
    retval->encrypt                 = encrypt;
    retval->check_password          = check_password;
    retval->decrypt                 = decrypt;
    retval->rekey                   = rekey;
    retval->create_hash             = hash;
    retval->create_hmac             = hmac;
    retval->random                  = mftahrand;
    retval->get_decrypted_header    = get_decrypted_header;
    retval->refresh_state           = refresh_state;
    retval->yield_payload           = yield;

    return MFTAH_SUCCESS;
}



#endif   /* LIBMFTAH_VERSION_MAJOR == 1 */
