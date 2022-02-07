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

#include "rand_byte_ins.h"

#include <stdlib.h>
#include <string.h>

#include "common/types.h"
#include "mutate.h"
#include "prng.h"
#include "strategy.h"

#ifdef RAND_BYTE_INS_IS_MASTER
get_fuzzing_strategy_function get_fuzzing_strategy = rand_byte_ins_populate;
#endif

// update the rand_byte_ins strategy state.
static inline void
rand_byte_ins_update(strategy_state *state)
{
	strategy_state_update(state);
	prng_state_update((prng_state *)state->internal_state);
}

// serialize the rand_byte_ins strategy state.
static inline char *
rand_byte_ins_serialize(strategy_state *state)
{
	prng_state *prng_st = (prng_state *)state->internal_state;

	// serialize the prng state and the strategy_state
	char *s_prng_st = prng_state_serialize(prng_st);
	char *s_state   = strategy_state_serialize(state, "rand_byte_ins");

	// combine the result
	char *s_final = calloc(1, strlen(s_prng_st) + strlen(s_state) + 1);

	strcat(s_final, s_state);
	strcat(s_final, s_prng_st);

	free(s_prng_st);
	free(s_state);

	return s_final;
}

// deserialize the rand_byte_ins strategy state.
static inline strategy_state *
rand_byte_ins_deserialize(char *s_state, size_t s_state_size)
{
	// ptr to serialized prng state:
	// set ourselves to point just past the trailing "..." of the "strategy_state" yaml serialization
	char *s_prng_st = strstr(s_state, "...") + 4;

	// deserialize the serialized states.
	prng_state     *prng_st = prng_state_deserialize(s_prng_st, s_state_size - (size_t)(s_prng_st - s_state));
	strategy_state *state   = strategy_state_deserialize(s_state, s_state_size);

	state->internal_state = prng_st;

	return state;
}

// create a human-readable string that describes the strategy state.
static inline char *
rand_byte_ins_print(strategy_state *state)
{
	// serialize the prng state and strategy state
	char *p_state   = strategy_state_print(state, "rand_byte_ins");
	char *p_prng_st = prng_state_print((prng_state *)state->internal_state);

	// combine them into one buffer!
	char *p_both = calloc(1, strlen(p_state) + strlen(p_prng_st) + 1);

	strcat(p_both, p_state);
	strcat(p_both, p_prng_st);

	// don't need these anymore
	free(p_state);
	free(p_prng_st);

	return p_both;
}

// create a rand_byte_ins strategy_state object.
static inline strategy_state *
rand_byte_ins_create(u8 *seed, size_t max_size, ...)
{
	strategy_state *new_state = strategy_state_create(seed, max_size);
	new_state->internal_state = prng_state_create((u64)*new_state->seed, 0);
	return new_state;
}

// free a rand_byte_ins strategy_state object.
static inline void
rand_byte_ins_free(strategy_state *state)
{
	prng_state_free((prng_state *)state->internal_state);
	state->internal_state = NULL;
	strategy_state_free(state);
}

// copy a rand_byte_ins strategy_state object.
static inline strategy_state *
rand_byte_ins_copy(strategy_state *state)
{

	strategy_state *new_state    = strategy_state_copy(state);
	prng_state     *prng_st_copy = prng_state_copy((prng_state *)state->internal_state);

	new_state->internal_state = prng_st_copy;

	return new_state;
}

static inline size_t
rand_byte_ins(u8 *buf, size_t size, strategy_state *state)
{
	u64    pos      = state->iteration;
	size_t max_size = state->max_size;

	if (size >= max_size || pos >= max_size) {
		return 0;
	}

	u8 byte_to_ins = (u8)(prng_state_random((prng_state *)state->internal_state) % 255);
	byte_ins(buf, size, pos, byte_to_ins);

	return size + 1;
}

/* populates fuzzing_strategy structure */
void
rand_byte_ins_populate(fuzzing_strategy *strategy)
{
	strategy->version          = VERSION_ONE;
	strategy->name             = "rand_byte_ins";
	strategy->create_state     = rand_byte_ins_create;
	strategy->mutate           = rand_byte_ins;
	strategy->serialize        = rand_byte_ins_serialize;
	strategy->deserialize      = rand_byte_ins_deserialize;
	strategy->print_state      = rand_byte_ins_print;
	strategy->copy_state       = rand_byte_ins_copy;
	strategy->free_state       = rand_byte_ins_free;
	strategy->description      = "on the first iteration, inserts a random byte at position 0. On the next iteration, inserts a random byte at position 1, etc.";
	strategy->update_state     = rand_byte_ins_update;
	strategy->is_deterministic = true;
}
