#ifndef LIBMFTAH_PRNG_H
#define LIBMFTAH_PRNG_H

#include "mftah.h"


void
prng_init(
	mftah_immutable_protocol_t mftah
);


uint64_t
prng_next();


uint64_t
prng_next_bounded(
	const uint64_t low,
	const uint64_t high
);


#endif   /* LIBMFTAH_PRNG_H */
