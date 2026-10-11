/**
 * mftah.c
 * Implementations for the default 'libmftah' protocol methods.
 *
 *
 * Copyright (C) 2024-2026 Zack Puhl <github@xmit.xyz>
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

#include "../include/mftah.h"
#include "../include/aes.h"
#include "../include/sha256.h"
#include "../include/prng.h"


#define MAX(x,y) \
	(((x) >= (y)) ? (x) : (y))
#define MIN(x,y) \
	(((x) <= (y)) ? (x) : (y))


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
		= (const void *)((uint8_t *)(header_pointer) + sizeof(mftah_payload_header_t));



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
		aes_context,
		self->hooks.memcpy,
		(uint8_t *)sha256_key,
		(uint8_t *)iv
	);

	switch (work_order->type) {
		case MFTAH_WORK_TYPE_ENCRYPT:
			AES_CBC_encrypt_buffer(
				aes_context,
				work_order->location,
				work_order->length,
				progress ? progress->hook : NULL,
				progress ? progress->context : NULL
			);
			break;
		case MFTAH_WORK_TYPE_DECRYPT:
			AES_CBC_decrypt_buffer(
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
	PRINTLN(MFTAH_LEVEL_DEBUG, "Mixing initialization vectors (%u : %u).", threads, header->nonce_seed_step);
	uint8_t *mixed_vectors = self->hooks.calloc(1, (threads * sizeof(header->nonce)));

	/* The first IV is equivalent to the "public" one used on the header. */
	self->hooks.memcpy(mixed_vectors,
					   header->nonce,
					   sizeof(header->nonce));
	MEMDUMP_MSG(mixed_vectors, sizeof(header->nonce), "\nIV #0:");

	/* The rest of them sequentially mix with the previous vector. */
	/* NOTE: We only go up to 'threads-1' because the first IV is already set up (see above). */
	for (uint8_t t = 0; t < (threads - 1); ++t) {
		size_t iv_base_offset = (t + 1) * sizeof(header->nonce);

		/* Only include the 'step' in the XOR if all seeds have already been used once. */
		uint8_t step = (threads >= sizeof(header->nonce_seeds)) ? header->nonce_seed_step : 0x00;

		/* The index of which seed to use depends on whether we've wrapped around once.
			And the value AT sizeof(seeds) is NOT included in this rotation. */
		uint8_t seed_position = t < sizeof(header->nonce_seeds) ? t : (t % sizeof(header->nonce_seeds));

		/* When the thread count has first passed the seeds available, use just the 'seed-step' to XOR the IV. */
		uint8_t seed = (threads == sizeof(header->nonce_seeds)) ? 0x00 : (header->nonce_seeds[seed_position]);

		PRINTLN(MFTAH_LEVEL_DEBUG, "MIX -- (%u : %u : %u)", (t + 1), step, seed_position);

		/* Now that we've got what we need, do the XOR. */
		for (size_t x = 0; x < sizeof(header->nonce); ++x) {
			mixed_vectors[iv_base_offset + x]
				= (
					mixed_vectors[(iv_base_offset + x) - sizeof(header->nonce)]
					^ (step ^ seed)
				);
		}

		/* Dump it so it's visible during debugging. */
		MEMDUMP_MSG(((size_t)mixed_vectors + iv_base_offset), sizeof(header->nonce), "IV #%u:", (t + 1));
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

	PRINTLN(MFTAH_LEVEL_DEBUG, "=== REGISTER call (completed) ===");

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
	PRINTLN(MFTAH_LEVEL_DEBUG, "=== CREATE call ===");

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
		new_payload->actual_data_length = buffer_length - sizeof(mftah_payload_header_t);

		self->refresh_state(self, new_payload);
		return MFTAH_SUCCESS;
	}

	PRINTLN(MFTAH_LEVEL_DEBUG, "Read blob from input; creating new payload_header stub.");

	/* Scaffold the new payload meta and header. */
	new_payload->actual_data_length = buffer_length;

	/* Allocate the adjusted buffer and copy the provided payload. */
	PRINTLN(MFTAH_LEVEL_DEBUG, "Reallocating buffer with an extra %llu bytes.", sizeof(mftah_payload_header_t));
	new_payload->buffer_base
		= (uint8_t *)(self->hooks.realloc((uint8_t *)buffer, buffer_length + sizeof(mftah_payload_header_t)));
	if (NULL == new_payload->buffer_base) {
		return MFTAH_OUT_OF_RESOURCES;
	}

	self->hooks.memmove(new_payload->buffer_base + sizeof(mftah_payload_header_t), new_payload->buffer_base, buffer_length);
	self->hooks.memset(new_payload->buffer_base, 0x00, sizeof(mftah_payload_header_t));

	/* Reassign the header pointer to the new location. */
	header = (mftah_payload_header_t *)new_payload->buffer_base;

	/* Refresh the state of the payload and indicate the final length. */
	if (NULL != new_payload_len) {
		*new_payload_len = buffer_length + sizeof(mftah_payload_header_t);
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

	PRINTLN(MFTAH_LEVEL_DEBUG, "=== ENCRYPT call ===");

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
			payload->actual_data_length + sizeof(mftah_payload_header_t) + remainder
		);
		if (NULL == new_buffer_base) {
			return MFTAH_OUT_OF_RESOURCES;
		}

		if (payload->buffer_base != new_buffer_base) {
			payload->buffer_base = new_buffer_base;

			payload_base = payload->buffer_base + sizeof(mftah_payload_header_t);
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
						  sizeof(header->nonce),
						  header->nonce);
	if (MFTAH_ERROR(status)) {
		return MFTAH_BAD_IV;
	}

	/* Randomize the seven possible IV mixer seeds. */
	PRINTLN(MFTAH_LEVEL_DEBUG, "Creating the initialization vector seeds.");
	status = self->random(self,
						  0,
						  0,
						  sizeof(header->nonce_seeds),
						  header->nonce_seeds);
	if (MFTAH_ERROR(status)) {
		return MFTAH_BAD_NONCE_SEEDS;
	}

	/* Randomize the IV step value. This CANNOT be zero. */
	PRINTLN(MFTAH_LEVEL_DEBUG, "Initializing the IV step value.");
	do {
		status = self->random(self,
							  0,
							  0,
							  sizeof(header->nonce_seed_step),
							  &(header->nonce_seed_step));
	} while (0 == header->nonce_seed_step);

	MEMDUMP_MSG(password_hash, SIZE_OF_SHA_256_HASH, "Got loaded password hash:");
	MEMDUMP_MSG(header->nonce, sizeof(header->nonce), "Using first IV:");
	MEMDUMP_MSG(header->signature, MFTAH_PAYLOAD_SIGNATURE_SIZE, "Original Signature:");
	MEMDUMP_MSG(header->nonce_seeds, sizeof(header->nonce_seeds), "IV Seeds:"); PRINT(MFTAH_LEVEL_DEBUG, "\n");
	MEMDUMP_MSG(&(header->nonce_seed_step), sizeof(header->nonce_seed_step), "Seed step value:"); PRINT(MFTAH_LEVEL_DEBUG, "\n");

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
				   (immutable_ref_t)header->nonce,
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
					   (immutable_ref_t)&(mixed_vectors[t * sizeof(header->nonce)]),
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
		(mftah_payload_header_t *)self->hooks.calloc(1, sizeof(mftah_payload_header_t));
	uint8_t encrypted_region_length = sizeof(mftah_payload_header_t) - MFTAH_HEADER_ENCRYPT_OFFSET;
	mftah_work_order_t new_order = {0};
	uint8_t password_hash[SIZE_OF_SHA_256_HASH] = {0};

	PRINTLN(MFTAH_LEVEL_DEBUG, "=== GET DECRYPTED HEADER call ===");

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
	self->hooks.memcpy(header_copy, header, sizeof(mftah_payload_header_t));

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
							header->nonce,
							NULL);
	if (MFTAH_ERROR(status)) {
		self->hooks.free(header_copy);
		return status;
	}

	PRINTLN(MFTAH_LEVEL_DEBUG, "Decrypted header.");
	MEMDUMP(header_copy, sizeof(mftah_payload_header_t));

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

	PRINTLN(MFTAH_LEVEL_DEBUG, "=== CHECK PASSWORD call ===");

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

	PRINTLN(MFTAH_LEVEL_DEBUG, "=== DECRYPT call ===");

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
		header->nonce_seed_step,
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
					   (immutable_ref_t)&(mixed_vectors[t * sizeof(header->nonce)]),
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

	PRINTLN(MFTAH_LEVEL_DEBUG, "=== REKEY call ===");

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

	PRINTLN(MFTAH_LEVEL_DEBUG, "=== CREATE HASH call ===");

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

	calc_sha_256(
		self->hooks.memcpy,
		self->hooks.memset,
		intermediate_result,
		input,
		input_length
	);

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

	PRINTLN(MFTAH_LEVEL_DEBUG, "=== CREATE HMAC call ===");

	if (
		NULL == self
		|| NULL == input || 0 == input_length
		|| NULL == key || 0 == key_length
		|| NULL == result
		|| (NULL != result_length && 0 == *result_length)
	) {
		return MFTAH_INVALID_PARAMETER;
	}

	hmac_sha256(
		self->hooks.memcpy,
		self->hooks.memset,
		key,
		key_length,
		input,
		input_length,
		intermediate_result
	);

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

	PRINTLN(MFTAH_LEVEL_DEBUG, "=== RANDOM call ===");

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
	PRINTLN(MFTAH_LEVEL_DEBUG, "=== REFRESH STATE call ===");

	if (NULL == payload) {
		return MFTAH_INVALID_PARAMETER;
	}

	EXTRACT_HEADER(payload->buffer_base)

	MEMDUMP(header, sizeof(mftah_payload_header_t));

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

	PRINTLN(MFTAH_LEVEL_DEBUG, "=== YIELD call ===");

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
/* Streaming protocol declarations. */
static
mftah_status_t
mftah_stream_register(
	IN mftah_stream_immutable_protocol_t self,
	IN CONST mftah_registration_details_t *CONST registration_details
) {
	if (NULL == self || NULL == registration_details)
		return MFTAH_INVALID_PARAMETER;
	registration_details->memcpy(
		(void *restrict)&(self->hooks),
		registration_details,
		sizeof(mftah_registration_details_t)
	);
	PRINTLN(MFTAH_LEVEL_DEBUG, "=== STREAM REGISTER call (completed) ===");
	return MFTAH_SUCCESS;
}


static
mftah_status_t
mftah_stream_init(
	IN mftah_stream_immutable_protocol_t self,
	IN MftahMode stream_mode,
	IN immutable_ref_t key,
	IN uint64_t key_length,
	IN uint64_t base_block_size,
	IN mftah_fp__yield_callback yield_callback,
	OUT mftah_stream_context_t **new_context
) {
	mftah_stream_context_t *new_ctx;
	PRINTLN(MFTAH_LEVEL_DEBUG, "=== STREAM INIT call ===");
	if (NULL == self || NULL == yield_callback || NULL == new_context
		|| (MFTAH_MODE_ENCRYPT != stream_mode && MFTAH_MODE_DECRYPT != stream_mode)
	) return MFTAH_INVALID_PARAMETER;
	else if (
		base_block_size < MFTAH_STREAM_MIN_FACTOR
		|| base_block_size > MFTAH_STREAM_MAX_FACTOR
	) return MFTAH_BAD_block_size;

	new_ctx = self->hooks.calloc(1, sizeof(mftah_stream_context_t));
	if (NULL == new_ctx) return MFTAH_OUT_OF_RESOURCES;

	new_ctx->mode = stream_mode;
	new_ctx-> block_size = mftah_get_stream_bufsz(base_block_size);
	new_ctx->yield_callback = yield_callback;

	new_ctx->stream_buffer = self->hooks.malloc(new_ctx->block_size);
	if (NULL == new_ctx->stream_buffer) return MFTAH_OUT_OF_RESOURCES;

	new_ctx->input_header = self->hooks.calloc(1, sizeof(mftah_payload_header_t));
	if (NULL == new_ctx->input_header) return MFTAH_OUT_OF_RESOURCES;
	new_ctx->constructed_header = self->hooks.calloc(1, sizeof(mftah_payload_header_t));
	if (NULL == new_ctx->constructed_header) return MFTAH_OUT_OF_RESOURCES;

	new_ctx->ohmac = self->hooks.calloc(1, SIZE_OF_SHA_256_HASH);// TODO: pinned to HMAC-SHA256
	if (NULL == new_ctx->ohmac) return MFTAH_OUT_OF_RESOURCES;
	new_ctx->ohmac_context = self->hooks.calloc(1, sizeof(HmacSha256Context));
	if (NULL == new_ctx->ohmac_context) return MFTAH_OUT_OF_RESOURCES;
	hmac_sha256_init(
		new_ctx->ohmac_context,
		self->hooks.memcpy,
		self->hooks.memset,
		(const void *)key,
		(size_t)key_length
	);

	new_ctx->whmac = self->hooks.calloc(1, SIZE_OF_SHA_256_HASH);// TODO: pinned to HMAC-SHA256
	if (NULL == new_ctx->whmac) return MFTAH_OUT_OF_RESOURCES;
	new_ctx->whmac_context = self->hooks.calloc(1, sizeof(HmacSha256Context));
	if (NULL == new_ctx->whmac_context) return MFTAH_OUT_OF_RESOURCES;
	hmac_sha256_init(
		new_ctx->whmac_context,
		self->hooks.memcpy,
		self->hooks.memset,
		(const void *)key,
		(size_t)key_length
	);

	new_ctx->hashed_key = self->hooks.malloc(SIZE_OF_SHA_256_HASH);
	if (NULL == new_ctx->hashed_key) return MFTAH_OUT_OF_RESOURCES;
	calc_sha_256(
		self->hooks.memcpy,
		self->hooks.memset,
		new_ctx->hashed_key,
		(const void *)key,
		(size_t)key_length
	);

	new_ctx->current_nonce = self->hooks.malloc(AES_BLOCKLEN);// TODO: pinned to AES-CBC
	if (NULL == new_ctx->current_nonce) return MFTAH_OUT_OF_RESOURCES;

	new_ctx->crypt_ctx = self->hooks.calloc(1, sizeof(aes_ctx_t));
	if (NULL == new_ctx->crypt_ctx) return MFTAH_OUT_OF_RESOURCES;

	/* If the mode is DECRYPT, initialize some necessary shadow buffers. */
	if (MFTAH_MODE_DECRYPT == stream_mode)
	{
		new_ctx->prev_buffer = self->hooks.calloc(1, new_ctx->block_size);
		if (NULL == new_ctx->prev_buffer) return MFTAH_OUT_OF_RESOURCES;
		new_ctx->prev_nonce = self->hooks.calloc(1, AES_BLOCKLEN);
		if (NULL == new_ctx->prev_nonce) return MFTAH_OUT_OF_RESOURCES;
	}

	*new_context = new_ctx;

	PRINTLN(MFTAH_LEVEL_DEBUG, "== STREAM INIT call (completed) ===");
	return MFTAH_SUCCESS;
}


static
mftah_status_t
mftah_stream_check_password(
	IN mftah_stream_immutable_protocol_t self,
	IN mftah_stream_context_t *context
) {
	PRINTLN(MFTAH_LEVEL_DEBUG, "=== STREAM CHECK PASSWORD call ===");

	if (0 == context->block_counter)
		return MFTAH_MISPLACED_PASSWORD_CHECK;
	self->hooks.memcpy(
		context->input_header,
		context->stream_buffer,
		sizeof(mftah_payload_header_t)
	);

	PRINTLN(MFTAH_LEVEL_DEBUG, "Read stream payload header...");
	MEMDUMP(context->input_header, sizeof(mftah_payload_header_t));

	/* Ensure the payload is designated as a stream type, or this won't work. */
	if (
		0 == context->input_header->stream_flags.stream
		|| context->input_header->stream_flags.canary
	) return MFTAH_INVALID_STREAM_STATE;

	if (!context->prefilled_input_header)
	{
		AES_init_ctx_iv(
			(aes_ctx_t *)context->crypt_ctx,
			self->hooks.memcpy,
			context->hashed_key,
			context->input_header->nonce
		);
		PRINTLN(MFTAH_LEVEL_DEBUG, "Forming streamed header decryption work order.");
		mftah_work_order_t new_order = {
			.type = MFTAH_WORK_TYPE_DECRYPT,
			.location = &((uint8_t *)context->input_header)[MFTAH_HEADER_ENCRYPT_OFFSET],
			.length = MFTAH_HEADER_ENCRYPT_ADDL_SIZE,
			.thread_index = 0,
			.suppress_progress = 1
		};
		mftah_status_t crypt_status = MFTAH_CRYPT_HOOK_DEFAULT(
			(mftah_immutable_protocol_t)self,
			&new_order,
			(immutable_ref_t)context->hashed_key,
			(immutable_ref_t)context->input_header->nonce,
			NULL
		);
		if(MFTAH_ERROR(crypt_status))
			return crypt_status;
	}

	if (0 != self->hooks.memcmp(
		context->input_header->signature,
		MftahPayloadSignature,
		MFTAH_PAYLOAD_SIGNATURE_SIZE)
	) return MFTAH_INVALID_PASSWORD;

	PRINTLN(MFTAH_LEVEL_DEBUG, "=== STREAM CHECK PASSWORD call (completed) ===");
	return MFTAH_SUCCESS;
}


static
mftah_status_t
mftah_stream_encrypt_next(
	IN mftah_stream_immutable_protocol_t self,
	IN uint64_t length,
	IN mftah_stream_context_t *context
) {
	mftah_status_t status = MFTAH_SUCCESS;
	size_t block_padding = 0;
	uint64_t original_length = length;
	mftah_work_order_t new_order = {
		.type = MFTAH_WORK_TYPE_ENCRYPT,
		.thread_index = 0,
		.suppress_progress = 1
	};
	PRINTLN(MFTAH_LEVEL_DEBUG, "=== STREAM ENCRYPT NEXT call ===");

	if (0 == context->block_counter)   /* First block? */
	{
		// TODO: perhaps this could be moved to another function
		mftah_status_t rand_status = mftahrand(
			(mftah_immutable_protocol_t)self,
			0,
			0,
			AES_BLOCKLEN,
			context->current_nonce
		);
		if (MFTAH_ERROR(rand_status)) return rand_status;

		mftah_payload_header_t *hdr = context->constructed_header;
		self->hooks.memcpy(hdr->nonce, context->current_nonce, AES_BLOCKLEN);
		rand_status = mftahrand(
			(mftah_immutable_protocol_t)self, 0, 0, sizeof(hdr->nonce_seeds), hdr->nonce_seeds);
		if (MFTAH_ERROR(rand_status)) return rand_status;
		hdr->stream_flags = (MftahStreamFlags){
			.stream = 1,
			.canary = 0,
			.block_size = ((context->block_size / (1ULL << 18)) >> 4ULL) & 0x1F
		};
		self->hooks.memcpy(hdr->magic, MftahMagic, MFTAH_MAGIC_SIGNATURE_SIZE);
		self->hooks.memcpy(hdr->signature, MftahPayloadSignature, MFTAH_PAYLOAD_SIGNATURE_SIZE);
		hdr->version_info[0] = LIBMFTAH_VERSION_MAJOR;
		hdr->version_info[1] = LIBMFTAH_VERSION_MINOR;
		hdr->version_info[2] = LIBMFTAH_VERSION_PATCH;
		// TODO: init other header fields here

		/* Duplicate and encrypt the tail end of the header. */
		mftah_payload_header_t *dupe = self->hooks.malloc(sizeof(mftah_payload_header_t));
		if (NULL == dupe) return MFTAH_OUT_OF_RESOURCES;
		self->hooks.memcpy(dupe, hdr, sizeof(mftah_payload_header_t));

		new_order.location = &((uint8_t* )hdr)[MFTAH_HEADER_ENCRYPT_OFFSET];
		new_order.length = MFTAH_HEADER_ENCRYPT_ADDL_SIZE;
		status = MFTAH_CRYPT_HOOK_DEFAULT(
			(mftah_immutable_protocol_t)self,
			&new_order,
			(immutable_ref_t)context->hashed_key,
			(immutable_ref_t)context->current_nonce,
			NULL
		);
		if (MEWL_ERROR(status)) return status;

		/* Yield the initial thin payload header. */
		// TODO: Think this data must be randomized before being sent?
		//   ^ before the con-header fields are filled here
		context->yield_callback((uint8_t *)hdr, sizeof(mftah_payload_header_t));
		context->yielded_bytes += sizeof(mftah_payload_header_t);   // TODO why isn't this just done inside the yield cb?
		self->hooks.free(dupe);
	}

	/* Roll the nonce data for the next block based on the seeds array and the current block number.
		This purposefully happens on the first block of encrypted data to prevent nonce reuse. */
	for (int i = 0; i < AES_BLOCKLEN; ++i)
		context->current_nonce[i] ^= (
			context->constructed_header->nonce_seeds[
				context->block_counter % sizeof(context->constructed_header->nonce_seeds)
			] ^ context->hashed_key[i]
		);

	/* Record the plaintext block to the O-HMAC context. */
	hmac_sha256_write(
		(HmacSha256Context *)context->ohmac_context,
		context->stream_buffer,
		length
	);

	/* If this is the last block, take care of padding to round the block. */
	// TODO: PKCS7 padding, not w/e tf this is
	if (length != context->block_size)
	{
		if (!(length % AES_BLOCKLEN))
		{
			if (length + sizeof(mftah_payload_header_t) < context->block_size) goto nopadding;
		}
		else
		{
			block_padding = AES_BLOCKLEN - (length % AES_BLOCKLEN);
			length += block_padding;
		}
		if (length + sizeof(mftah_payload_header_t) >= context->block_size)
		{
			PRINTLN(MFTAH_LEVEL_DEBUG, "Forwarding trailing header to a final stream block.");
			block_padding += (context->block_size - length);
			length = context->block_size;
		}
		/* Turn padding into 0xFF bytes. */
		self->hooks.memset(
			&context->stream_buffer[original_length],
			0xFF,
			block_padding
		);
	}

nopadding:
	/* Encrypt... */
	new_order.length = length;
	new_order.location = context->stream_buffer;
	status = MFTAH_CRYPT_HOOK_DEFAULT(
		(mftah_immutable_protocol_t)self,
		&new_order,
		(immutable_ref_t)context->hashed_key,
		(immutable_ref_t)context->current_nonce,
		NULL
	);
	if (MFTAH_ERROR(status)) return status;

	/* Update the W-HMAC context with the ciphertext. */
	hmac_sha256_write(
		(HmacSha256Context *)context->whmac_context,
		context->stream_buffer,
		length
	);

	/* Yield ciphertext. */
	context->yield_callback(context->stream_buffer, length);
	context->yielded_bytes += length;

	/* This condition indicates the final stream block has been reached, */
	if (original_length != context->block_size)
	{
		/* Wrap up the final trailing header stub. */
		context->last_block_remainder_length = original_length;
		context->constructed_header->payload_length =
			(context->block_size * context->block_counter) + original_length;

		hmac_sha256_close((HmacSha256Context *)context->ohmac_context, context->ohmac);
		// TODO: store O-HMAC
		hmac_sha256_close((HmacSha256Context *)context->whmac_context, context->whmac);
		// TODO: store W-HMAC

		mftah_payload_header_t *dupe = self->hooks.malloc(sizeof(mftah_payload_header_t));
		if (NULL == dupe) return MFTAH_OUT_OF_RESOURCES;
		self->hooks.memcpy(dupe, context->constructed_header, sizeof(mftah_payload_header_t));

		new_order.location = &((uint8_t *)dupe)[MFTAH_HEADER_ENCRYPT_OFFSET];
		new_order.length = MFTAH_HEADER_ENCRYPT_ADDL_SIZE;
		status = MFTAH_CRYPT_HOOK_DEFAULT(
			(mftah_immutable_protocol_t)self,
			&new_order,
			(immutable_ref_t)context->hashed_key,
			(immutable_ref_t)context->constructed_header->nonce,
			NULL
		);
		if (MFTAH_ERROR(status)) return status;

		/* Yield the final trailing header. */
		context->yield_callback((uint8_t *)dupe, sizeof(mftah_payload_header_t));
		context->yielded_bytes += sizeof(mftah_payload_header_t);
		self->hooks.free(dupe);
	}
	else   /* else, not the final block: increment counter */
	{
		++context->block_counter;
	}

	PRINTLN(MFTAH_LEVEL_DEBUG, "=== STREAM ENCRYPT NEXT call (completed) ===");
	return MFTAH_SUCCESS;
}


static
mftah_status_t
mftah_stream_decrypt_next(
	IN mftah_stream_immutable_protocol_t self,
	IN uint64_t length,
	IN mftah_stream_context_t *context
) {
	uint8_t *scroll = context->stream_buffer;
	uint64_t original_length = length;
	mftah_status_t status = MFTAH_SUCCESS;
	mftah_work_order_t new_order = {
		.type = MFTAH_WORK_TYPE_DECRYPT,
		.suppress_progress = 1,
		.thread_index = 0
	};
	PRINTLN(MFTAH_LEVEL_DEBUG, "=== STREAM DECRYPT NEXT call ===");

	if (0 == context->block_counter)
	{
		if (!context->prefilled_input_header)
		{
			if (length < sizeof(mftah_payload_header_t))
				return MFTAH_BAD_STREAM_PAYLOAD_LENGTH;

			mftah_status_t pass_status = mftah_stream_check_password(self, context);
			if (MFTAH_ERROR(pass_status)) return pass_status;

			scroll += sizeof(mftah_payload_header_t);
			length -= sizeof(mftah_payload_header_t);
		}
		self->hooks.memcpy(context->current_nonce, context->input_header->nonce, AES_BLOCKLEN);
	}

	/* Roll the nonce according to the payload's properties. */
	for (int i = 0; i < AES_BLOCKLEN; ++i)
		context->current_nonce[i] ^= (
			context->constructed_header->nonce_seeds[
				context->block_counter % sizeof(context->constructed_header->nonce_seeds)
			] ^ context->hashed_key[i]
		);

	/**
	 * Stream-based decryption functions differently from encryption:
	 * - Payload contents are read and stored into a shadow buffer block-by-block
	 * - The shadow buffer is decrypted given that the NEXT stream block is not the final one.
	 * - Once the final block is detected, the trailing payload header is extracted and decrypted.
	 * - The penultimate (shadow) block is decrypted along with the final one, and the output is
	 *    trimmed to match the specified length in the trailing header, thus removing any padding.
	 */
	/* The final block is always indicated by an incomplete stream block length. */
	if (original_length != context->block_size)
	{
		/* The final block must contain at least an untruncated MFTAH header. */
		if (original_length < sizeof(mftah_payload_header_t))
			return MFTAH_BAD_STREAM_PAYLOAD_LENGTH;

		self->hooks.memcpy(
			context->constructed_header,
			&scroll[length - sizeof(mftah_payload_header_t)],
			sizeof(mftah_payload_header_t)
		);
		if (0 != self->hooks.memcmp(
			context->constructed_header, MftahMagic, MFTAH_MAGIC_SIGNATURE_SIZE)
		) return MFTAH_STREAM_MISSING_POST_HEADER;

		new_order.location
			= &((uint8_t *)(context->constructed_header))[MFTAH_HEADER_ENCRYPT_OFFSET];
		new_order.length = MFTAH_HEADER_ENCRYPT_ADDL_SIZE;
		status = MFTAH_CRYPT_HOOK_DEFAULT(
			(mftah_immutable_protocol_t)self,
			&new_order,
			(immutable_ref_t)context->hashed_key,
			(immutable_ref_t)context->constructed_header->nonce,
			NULL
		);
		if (MFTAH_ERROR(status)) return status;

		length -= sizeof(mftah_payload_header_t);   /* adjust for the trailing header */
		uint64_t payload_len = context->constructed_header->payload_length;
		PRINTLN(MFTAH_LEVEL_DEBUG, "Got actual payload length of %lu bytes.", payload_len);
		PRINTLN(
			MFTAH_LEVEL_DEBUG,
			"===> Length comps: [ len %lu (orig %lu) | yield %lu | prev %lu / report %lu ]",
			length, original_length, context->yielded_bytes,
			context->prev_buffer_length, payload_len
		);

		/* Once the trailing header is decrypted, check the marked length within in. It's possible
		   that this content block only consists of a header, meaning the shadow/prev block contains
		   the 0xFF padding. We must trim and discard that during the decryption process. */
		int ends_in_prev_block = 0;
		if (0 != context->block_counter)  /* prev buffer only exists when this is true */
		{
			/* Record the shadow buffer to the W-HMAC context. */
			hmac_sha256_write(
				(HmacSha256Context *)context->whmac_context,
				context->prev_buffer,
				context->prev_buffer_length
			);
			/* Decrypt the shadow buffer. */
			new_order.location = context->prev_buffer;
			new_order.length = context->prev_buffer_length;
			status = MFTAH_CRYPT_HOOK_DEFAULT(
				(mftah_immutable_protocol_t)self,
				&new_order,
				(immutable_ref_t)context->hashed_key,
				(immutable_ref_t)context->prev_nonce,
				NULL
			);
			/* Adjust content length to match the actual payload length. */
			if (context->yielded_bytes + context->prev_buffer_length > payload_len)
			{
				context->prev_buffer_length = (payload_len - context->yielded_bytes);
				PRINTLN(
					MFTAH_LEVEL_DEBUG,
					"End of stream in prev block (len %lu -> yield %lu + prev %lu)",
					payload_len, context->yielded_bytes, context->prev_buffer_length
				);
				ends_in_prev_block = 1;
			}
			PRINTLN(
				MFTAH_LEVEL_DEBUG,
				"Penultimate stream block size %lu of %lu bytes",
				context->prev_buffer_length, context->block_size
			);
			/* Record decrypted contents into O-HMAC. */
			hmac_sha256_write(
				(HmacSha256Context *)context->ohmac_context,
				(immutable_ref_t)context->prev_buffer,
				(immutable_ref_t)context->prev_buffer_length
			);
			/* At last, yield the contents of the previous block. */
			context->yield_callback(context->prev_buffer, context->prev_buffer_length);
			context->yielded_bytes += context->prev_buffer_length;
		}   /* if [prev buffer exists] */

		/* Now that the previous buffer has been handled, finish with the final block. */
		if (!ends_in_prev_block && length > 0)
		{
			/* Record to W-HMAC. */
			hmac_sha256_write(
				(HmacSha256Context *)context->whmac_context,
				context->stream_buffer,
				length
			);
			/* Decrypt. */
			new_order.location = context->stream_buffer;
			new_order.length = length;
			status = MFTAH_CRYPT_HOOK_DEFAULT(
				(mftah_immutable_protocol_t)self,
				&new_order,
				(immutable_ref_t)context->hashed_key,
				(immutable_ref_t)context->current_nonce,
				NULL
			);
			if (MFTAH_ERROR(status)) return status;
			/* Trim padding for O-HMAC measurement. */
			length = payload_len - context->yielded_bytes;
			PRINTLN(MFTAH_LEVEL_DEBUG, "Final block %lu bytes", length);
			/* Record to O-HMAC. */
			hmac_sha256_write(
				(HmacSha256Context *)context->ohmac_context,
				context->stream_buffer,
				length
			);
			/* Yield the block. */
			context->yield_callback(context->stream_buffer, length);
			context->yielded_bytes += length;
		} /* if [has final block contents] */

		/* Seal up the HMACs and compare them to the ones in the decrypted trailing header. */
		hmac_sha256_close((HmacSha256Context *)context->whmac_context, context->whmac);
		PRINTLN(MFTAH_LEVEL_DEBUG, "Comparing W-HMAC [calc vs. found]...");
		MEMDUMP(context->whmac, SIZE_OF_SHA_256_HASH);
		MEMDUMP(context->constructed_header->wrapper_hmac, SIZE_OF_SHA_256_HASH);
		if (0 != self->hooks.memcmp(
			context->constructed_header->wrapper_hmac,
			context->whmac,
			SIZE_OF_SHA_256_HASH
		)) return MFTAH_BAD_W_HMAC;

		hmac_sha256_close((HmacSha256Context *)context->ohmac_context, context->ohmac);
		PRINTLN(MFTAH_LEVEL_DEBUG, "Comparing O-HMAC [calc vs. found]...");
		MEMDUMP(context->ohmac, SIZE_OF_SHA_256_HASH);
		MEMDUMP(context->constructed_header->original_hmac, SIZE_OF_SHA_256_HASH);
		if (0 != self->hooks.memcmp(
			context->constructed_header->original_hmac,
			context->ohmac,
			SIZE_OF_SHA_256_HASH
		)) return MFTAH_BAD_O_HMAC;

		PRINTLN(MFTAH_LEVEL_DEBUG, "=== STREAM DECRYPT NEXT call (completed) - END ===");
		return MFTAH_SUCCESS;
	} /* if [final block of stream] */

	/* === This code only runs for blocks that are full-sized and not the end of the stream. === */

	/* Record the shadow buffer to the W-HMAC context. */
	hmac_sha256_write(
		(HmacSha256Context *)context->whmac_context,
		context->prev_buffer,
		context->prev_buffer_length
	);
	/* Decrypt. */
	new_order.location = context->prev_buffer;
	new_order.length = context->prev_buffer_length;
	status = MFTAH_CRYPT_HOOK_DEFAULT(
		(mftah_immutable_protocol_t)self,
		&new_order,
		(immutable_ref_t)context->hashed_key,
		(immutable_ref_t)context->prev_nonce,
		NULL
	);
	if (MFTAH_ERROR(status)) return status;
	/* Record decrypted contents to the O-HMAC context. */
	hmac_sha256_write(
		(HmacSha256Context *)context->ohmac_context,
		context->prev_buffer,
		context->prev_buffer_length
	);
	/* Yield. */
	context->yield_callback(context->prev_buffer, context->prev_buffer_length);
	context->yielded_bytes += context->prev_buffer_length;

	/* Track the nonce state. */
	self->hooks.memcpy(context->prev_nonce, context->current_nonce, AES_BLOCKLEN);

	/* Instead of copying into the shadow buffer, just free the old pointer and swap. */
	self->hooks.free(context->prev_buffer);
	context->prev_buffer = context->stream_buffer;
	context->prev_buffer_length = length;
	context->stream_buffer = self->hooks.malloc(context->block_size);

	/* Increment block counter. */
	++context->block_counter;

	PRINTLN(MFTAH_LEVEL_DEBUG, "=== STREAM DECRYPT NEXT call (completed) - END ===");
	return MFTAH_SUCCESS;
}


static
mftah_status_t
mftah_stream_process_next(
	IN mftah_stream_immutable_protocol_t self,
	IN uint64_t length,
	IN mftah_stream_context_t *context
) {
	PRINTLN(MFTAH_LEVEL_DEBUG, "=== STREAM PROCESS NEXT call ===");
	if (NULL == self || NULL == context)
		return MFTAH_INVALID_PARAMETER;
	return (MFTAH_MODE_DECRYPT == context->mode)
		? mftah_stream_decrypt_next(self, length, context)
		: mftah_stream_encrypt_next(self, length, context);
}


static
mftah_status_t
mftah_stream_close(
	IN mftah_stream_immutable_protocol_t self,
	IN mftah_stream_context_t *context
) {
	PRINTLN(MFTAH_LEVEL_DEBUG, "=== STREAM CLOSE ===");
	// TODO: Anything that
	return MFTAH_SUCCESS;
}


/****************************** */
/****************************** */
/****************************** */
/* Primary concrete module export. */
mftah_status_t
mftah_protocol_factory__create(
	mftah_protocol_t *retval
) {
	if (NULL == retval) return MFTAH_INVALID_PARAMETER;

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


mftah_status_t
mftah_stream_protocol_factory__create(
	mftah_stream_protocol_t *retval
) {
	if (NULL == retval) return MFTAH_INVALID_PARAMETER;
	retval->register_hooks		= mftah_stream_register;
	retval->init				= mftah_stream_init;
	retval->check_password		= mftah_stream_check_password;
	retval->process_next		= mftah_stream_process_next;
	retval->close				= mftah_stream_close;
	return MFTAH_SUCCESS;
}


const char *
mftah_status_to_string(
	mftah_status_t status
) {
	switch (status)
	{
		case MFTAH_SUCCESS:						return "Success";
		case MFTAH_FAIL_GENERIC:				return "Generic failure";
		case MFTAH_INVALID_PARAMETER:			return "Invalid parameter";
		case MFTAH_INVALID_ALIGNMENT:			return "Invalid alignment";
		case MFTAH_OUT_OF_RESOURCES:			return "Out of resources";
		case MFTAH_INVALID_SIGNATURE:			return "Invalid signature";
		case MFTAH_BAD_PAYLOAD_STATE:			return "Bad payload state";
		case MFTAH_PAYLOAD_NOT_DECRYPTED:		return "Payload not decrypted";
		case MFTAH_INVALID_PASSWORD:			return "Invalid password";
		case MFTAH_INVALID_THREAD_COUNT:		return "Invalid thread count";
		case MFTAH_INVALID_ENCRYPTION_TYPE:		return "Invalid encryption type";
		case MFTAH_INVALID_HMAC_TYPE:			return "Invalid HMAC type";
		case MFTAH_MISPLACED_PASSWORD_CHECK:	return "Misplaced password check";
		case MFTAH_BAD_W_HMAC:					return "Bad wrapper HMAC";
		case MFTAH_BAD_O_HMAC:					return "Bad original HMAC";
		case MFTAH_BAD_PAYLOAD_LEN:				return "Bad payload length";
		case MFTAH_BAD_IV:						return "Bad initialization vector";
		case MFTAH_BAD_NONCE_SEEDS:				return "Bad initialization vector seeds";
		case MFTAH_BAD_PW_HASH:					return "Bad password hash";
		case MFTAH_THREAD_BUSY:					return "Thread busy";
		case MFTAH_INVALID_STREAM_STATE:		return "Invalid stream state";
		case MFTAH_BAD_block_size:		return "Bad stream block size";
		case MFTAH_BAD_STREAM_PAYLOAD_LENGTH:	return "Bad stream payload length";
		case MFTAH_STREAM_MISSING_POST_HEADER:	return "Missing stream post-header";
		case MFTAH_PREMATURE_END_OF_STREAM:		return "Premature end of stream";
		case MFTAH_STREAM_LAST_BLOCK_TOO_BIG:	return "Last block too large";
		default:								return "Unknown status";
	}
}


uint64_t
mftah_get_stream_bufsz(
	uint64_t factor
) {
	return ((factor << 4ULL) * (1ULL << 18));
}
