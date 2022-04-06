// DISTRIBUTION STATEMENT A. Approved for public release. Distribution
// is unlimited.
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

#include "rand_byte_replace.h"

#include <stdlib.h>
#include <string.h>

#include "common/types.h"
#include "prng.h"
#include "strategy.h"

#ifdef RAND_BYTE_REPLACE_IS_MASTER
get_fuzzing_strategy_function get_fuzzing_strategy = rand_byte_replace_populate;
#endif

// update a rand_byte_replace strategy state.
static inline void
rand_byte_replace_update(strategy_state *state)
{
	strategy_state_update(state);
	prng_state_update((prng_state *)state->internal_state);
}

// create a rand_byte_replace strategy state.
static inline strategy_state *
rand_byte_replace_create(u8 *seed, size_t max_size, size_t size, ...)
{
	strategy_state *new_state = strategy_state_create(seed, max_size, size);
	new_state->internal_state = prng_state_create((u64)*new_state->seed, 0);
	return new_state;
}

// serialize a rand_byte_replace strategy state.
static inline char *
rand_byte_replace_serialize(strategy_state *state)
{
	prng_state *prng_st = (prng_state *)state->internal_state;

	// seialize the state and the prng state
	char *s_prng_st = prng_state_serialize(prng_st);
	char *s_state   = strategy_state_serialize(state, "rand_byte_replace");

	size_t buflen = strlen(s_prng_st) + strlen(s_state);

	// combine to one chunk
	char *s_final = calloc(1, buflen + 1);

	strncat(s_final, s_state, buflen);
	strncat(s_final, s_prng_st, buflen);

	// don't need these anymore!
	free(s_prng_st);
	free(s_state);

	return s_final;
}

// deserialize a serialized rand_byte_replace strategy state.
static inline strategy_state *
rand_byte_replace_deserialize(char *s_state, size_t s_state_size)
{
	// ptr to serialized prng state:
	// set ourselves to point just past the trailing "..." of the "strategy_state" yaml serialization
	char *s_prng_st = strstr(s_state, "...") + 4;

	prng_state     *prng_st = prng_state_deserialize(s_prng_st, s_state_size - (size_t)(s_prng_st - s_state));
	strategy_state *state   = strategy_state_deserialize(s_state, s_state_size);

	state->internal_state = prng_st;

	return state;
}

// create a human-readble bytestring describing a rand_byte_replace strategy_state object.
static inline char *
rand_byte_replace_print(strategy_state *state)
{
	char *p_state   = strategy_state_print(state, "rand_byte_replace");
	char *p_prng_st = prng_state_print((prng_state *)state->internal_state);

	size_t buflen = strlen(p_state) + strlen(p_prng_st);
	char  *p_both = calloc(1, buflen + 1);

	strncat(p_both, p_state, buflen);
	strncat(p_both, p_prng_st, buflen);

	free(p_state);
	free(p_prng_st);

	return p_both;
}

// free a rand_byte_replace strategy_state.
static inline void
rand_byte_replace_free(strategy_state *state)
{
	prng_state_free((prng_state *)state->internal_state);
	state->internal_state = NULL;
	strategy_state_free(state);
}

// copy a rand_byte_replace strategy_state.
static inline strategy_state *
rand_byte_replace_copy(strategy_state *state)
{

	strategy_state *new_state    = strategy_state_copy(state);
	prng_state     *prng_st_copy = prng_state_copy((prng_state *)state->internal_state);

	new_state->internal_state = prng_st_copy;

	return new_state;
}

static inline size_t
rand_byte_replace(u8 *buf, size_t size, strategy_state *state)
{
	// save old state;
	prng_state orig_state;
	memcpy(&orig_state, state->internal_state, sizeof(prng_state));

	// byte_pos will be in range 0 - (size - 1), also updates prng since we need two numbers.
	size_t byte_pos = prng_state_UR((prng_state *)state->internal_state, (u32)size);

	// new_byte will be in range 0 - 255, does not update the prng.
	u8 new_byte = (u8)(prng_state_random((prng_state *)state->internal_state) % 256);

	// restore prng state to original so that the strategy is stateless.
	memcpy(state->internal_state, &orig_state, sizeof(prng_state));

	byte_replace(buf, size, byte_pos, new_byte);

	return size;
}

/* populates fuzzing_strategy structure */
void
rand_byte_replace_populate(fuzzing_strategy *strategy)
{
	strategy->version          = VERSION_ONE;
	strategy->name             = "rand_byte_replace";
	strategy->create_state     = rand_byte_replace_create;
	strategy->mutate           = rand_byte_replace;
	strategy->serialize        = rand_byte_replace_serialize;
	strategy->deserialize      = rand_byte_replace_deserialize;
	strategy->print_state      = rand_byte_replace_print;
	strategy->copy_state       = rand_byte_replace_copy;
	strategy->free_state       = rand_byte_replace_free;
	strategy->description      = "Replaces a single byte at a pseudorandom position with a new pseudorandom byte.";
	strategy->update_state     = rand_byte_replace_update;
	strategy->is_deterministic = false;
}
