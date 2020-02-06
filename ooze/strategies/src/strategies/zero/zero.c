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

#include "zero.h"

#include <stddef.h>

#include "strategy.h"

SERIALIZE_FUNC(zero_serialize, "zero")
PRINT_FUNC(zero_print, "zero")

#ifdef ZERO_IS_MASTER
get_fuzzing_strategy_function get_fuzzing_strategy = zero_populate;
#endif

/*
	Deterministically zeroizes the buffer.
*/
static inline size_t
zero(u8 *buf, size_t size, strategy_state *state)
{
	// bit to flip
	size_t current_pos = state->iteration;
	size_t last_pos    = size;

	if (current_pos < last_pos) {
		byte_replace(buf, size, current_pos, 0);
		return size;
	}

	current_pos -= last_pos;
	last_pos -= 1;

	if (current_pos < last_pos) {
		two_byte_replace(buf, size, current_pos, 0);
		return size;
	}

	current_pos -= last_pos;
	last_pos -= 2;

	if (current_pos < last_pos) {
		four_byte_replace(buf, size, current_pos, 0);
		return size;
	}

	current_pos -= last_pos;
	last_pos -= 4;

	if (current_pos < last_pos) {
		eight_byte_replace(buf, size, current_pos, 0);
		return size;
	}

	return 0;
}

/* populates fuzzing_strategy structure */
void
zero_populate(fuzzing_strategy *strategy)
{
	strategy->version          = VERSION_ONE;
	strategy->name             = "zero";
	strategy->create_state     = strategy_state_create;
	strategy->mutate           = zero;
	strategy->serialize        = zero_serialize;
	strategy->deserialize      = strategy_state_deserialize;
	strategy->print_state      = zero_print;
	strategy->copy_state       = strategy_state_copy;
	strategy->free_state       = strategy_state_free;
	strategy->description      = "Replaces every 8, 16, 32, and 64 bits with 0";
	strategy->update_state     = strategy_state_update;
	strategy->is_deterministic = true;
}
