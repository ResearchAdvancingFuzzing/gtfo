// DISTRIBUTION STATEMENT A. Approved for public release. Distribution is unlimited.
//
// This material is based upon work supported by the Department of the Air Force under Air Force Contract No. FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the Department of the Air Force.
//
// © 2019 Massachusetts Institute of Technology.
//
// Subject to FAR52.227-11 Patent Rights - Ownership by the contractor (May 2014)
//
// The software/firmware is provided to you on an As-Is basis
//
// Delivered to the U.S. Government with Unlimited Rights, as defined in DFARS Part 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed above. Use of this work other than as specifically authorized by the U.S. Government may violate any copyrights that exist in this work.

#include "common/yaml_helper.h"
#include "prng.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// *Really* minimal PCG32 code / (c) 2014 M.E. O'Neill / pcg-random.org
// Licensed under Apache License 2.0 (NO WARRANTY, etc. see website)
// Modified by Andy and Aaron

// this function creates a new prng_state object
prng_state *
prng_state_create(u64 new_state, u64 new_inc)
{
	prng_state *prng_st = calloc(1, sizeof(prng_state));
	prng_st->state      = new_state;
	prng_st->inc        = new_inc;

	return prng_st;
}

// this function creates a human-readable string describing a prng_state
inline char *
prng_state_print(prng_state *prng_st)
{
	char *str_buf = calloc(1, 128);

	snprintf(str_buf, 128, "pcg32 state: 0x%016" PRIX64 "\npcg32 inc: %" PRIu64 "\n", prng_st->state, prng_st->inc);

	return str_buf;
}

// this function frees a pcg32 state
inline void
prng_state_free(prng_state *prng_st)
{
	if (prng_st)
		free(prng_st);
}

// this function copies a pcg32 state
inline prng_state *
prng_state_copy(prng_state *prng_st)
{
	prng_state *new_state = calloc(1, sizeof(prng_state));
	memcpy(new_state, prng_st, sizeof(prng_state));
	return new_state;
}

// this function advances a pcg32 state
inline void
prng_state_update(prng_state *prng_st)
{
	prng_st->state = prng_st->state * 6364136223846793005ULL + (prng_st->inc | 1);
        //printf("2a. prng state: %lu\n", prng_st->state);
}

// this function gets a integer from a pcg32 state
inline uint32_t
prng_state_random(prng_state *prng_st)
{
	// Calculate output function (XSH RR), uses old state for max ILP
	uint32_t xorshifted = (u32)(((prng_st->state >> 18u) ^ prng_st->state) >> 27u);
        //printf("3. xorshifted: %u\n", xorshifted); 
	uint32_t rot        = (u32)(prng_st->state >> 59u);
        //printf("4. rot: %u\n", rot); 
	return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}

// Serialize a pcg32 state.
inline char *
prng_state_serialize(prng_state *prng_st)
{
	yaml_serializer *helper;
	char            *mybuffer;
	size_t           mybuffersize;

	helper = yaml_serializer_init("");

	// We want to name the structure for readability.
	YAML_SERIALIZE_NEST_MAP(helper, prng_state)
	YAML_SERIALIZE_START_MAPPING(helper)
	YAML_SERIALIZE_32HEX_KV(helper, version, 0)

	YAML_SERIALIZE_64HEX_KV(helper, state, prng_st->state)
	YAML_SERIALIZE_64HEX_KV(helper, inc, (u64)prng_st->inc)

	YAML_SERIALIZE_END_MAPPING(helper)
	yaml_serializer_end(helper, &mybuffer, &mybuffersize);

	return mybuffer;
}

// this function deserializes a pcg32 state
inline prng_state *
prng_state_deserialize(char *s_state, size_t s_state_size)
{
	prng_state        *prng_st = calloc(1, sizeof(prng_state));
	yaml_deserializer *helper;

	helper = yaml_deserializer_init(NULL, s_state, s_state_size);

	// Get to the document start
	YAML_DESERIALIZE_PARSE(helper)
	while (helper->event.type != YAML_DOCUMENT_START_EVENT) {
		YAML_DESERIALIZE_EAT(helper)
	}

	// Deserialize the prng_state structure:
	// This is coded like LL(1) parsing, not event-driven, because we only support one version of file_format_version and
	// no structure members are optional in the yaml file.

	u32 version = 0;

	YAML_DESERIALIZE_EAT(helper)
	YAML_DESERIALIZE_MAPPING_START(helper, "prng_state")

	// Deserialize the structure version. We have only one version, so we don't do anything with it.
	YAML_DESERIALIZE_GET_KV_U32(helper, "version", &version)

	YAML_DESERIALIZE_GET_KV_U64(helper, "state", &prng_st->state)
	YAML_DESERIALIZE_GET_KV_U64(helper, "inc", &prng_st->inc)
	YAML_DESERIALIZE_MAPPING_END(helper)

	yaml_deserializer_end(helper);

	return prng_st;
}

// this function gets a pseudorandom number from the prng
// and updates the prng's state.
inline u64
prng_state_UR(prng_state *prng_state, u64 limit)
{
	assert(limit != 0);
        //printf("0. limit: %lu\n", limit);
        //printf("1. oldstate: prng: state: %lu, limit: %lu\n", prng_state->state, prng_state->inc); 
        uint32_t ran = prng_state_random(prng_state);
	u64 retval = ran % limit;
        //printf("5.  retval= %d mod %lu = %lu, prng: state: %lu, limit: %lu\n", ran, limit, retval, prng_state->state, prng_state->inc); 
	prng_state_update(prng_state);

	return retval;
}
