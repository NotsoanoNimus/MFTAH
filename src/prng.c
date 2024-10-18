/**
 * @file prng.c
 * @brief PRNG implementations for MFTAH, using tinymt64 and Xoshiro128+.
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

#include "tinymt64.c"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"



static
void
prng_init(
    mftah_immutable_protocol_t mftah
);

static
uint64_t
prng_next();

static
uint64_t
prng_next_bounded(
    const uint64_t low,
    const uint64_t high
);



static uint64_t s[2];
static int s_seeded = 0;
static int s_mutex = 0;



static inline
uint64_t
rotl(const uint64_t x,
     int k)
{
    return ((x << k) | (x >> (64 - k)));
}


static inline
uint64_t
Xoshiro128p__next_bounded(uint64_t low,
                          uint64_t high)
{
    s_mutex = 1;

    const uint64_t range = 1 + high - low;

    const uint64_t s0 = s[0];
    uint64_t s1 = s[1];
    const uint64_t result = s0 + s1;

    s1 ^= s0;
    s[0] = rotl(s0, 24) ^ s1 ^ (s1 << 16);
    s[1] = rotl(s1, 37);

    s_mutex = 0;

    return (
        (high > low)
        * (
            (
                result
                % (
                    (
                        ((0 == range) * 1)
                        + range
                    )
                )
            )
            + low
        )
    );
}

static
void
Xoshiro128p__init(mftah_immutable_protocol_t mftah)
{
    uint64_t seed_value;
    unsigned int lo, hi;
    tinymt64_t* p_prng_init;

    s_mutex = 1;

    // Get the amount of cycles since the processor was powered on.
    //   This should act as a sufficient non-time-based PRNG seed.
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    seed_value = (((uint64_t)hi << 32) | lo);

    p_prng_init = (tinymt64_t*)mftah->hooks.calloc(1, sizeof(tinymt64_t));
    tinymt64_init(p_prng_init, seed_value);

    // Seed Xoshiro128+.
    s[0] = tinymt64_generate_uint64(p_prng_init);
    s[1] = tinymt64_generate_uint64(p_prng_init);

    mftah->hooks.free(p_prng_init);

    s_seeded = 1;
    s_mutex = 0;
}


static
void
prng_init(mftah_immutable_protocol_t mftah)
{
    while (0 != s_mutex);

    if (0 == s_seeded) {
        Xoshiro128p__init(mftah);
    }
}


static
uint64_t
prng_next()
{
    while (0 != s_mutex);

    return Xoshiro128p__next_bounded(0, UINT64_MAX - 1);
}


static
uint64_t
prng_next_bounded(const uint64_t low,
                  const uint64_t high)
{
    while (0 != s_mutex);

    return Xoshiro128p__next_bounded(low, high);
}



#pragma GCC diagnostic pop
