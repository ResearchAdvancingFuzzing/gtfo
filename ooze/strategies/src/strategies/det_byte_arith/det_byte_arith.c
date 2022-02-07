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

#include "det_byte_arith.h"

#include "afl_config.h"
#include "common/types.h"
#include "mutate.h"
#include "strategy.h"

SERIALIZE_FUNC(det_byte_arith_serialize, "det_byte_arith")
PRINT_FUNC(det_byte_arith_print, "det_byte_arith")

#ifdef DET_BYTE_ARITH_IS_MASTER
get_fuzzing_strategy_function get_fuzzing_strategy = det_byte_arith_populate;
#endif

static inline size_t
det_byte_arith(u8 *buf, size_t size, strategy_state *state)
{
	u64 range_len = MAX_ARITH * 2;                // how many iterations per byte
	u64 pos       = state->iteration / range_len; // which byte we are mutating

	if (pos >= state->max_size) {
		return 0;
	}
	// iter in range [0 -> 70]
	u8 iter = (u8)(state->iteration % range_len);

	// abs_val in range [ 1 -> 35]
	u8 abs_val = (u8)((iter / 2) + 1);
	u8 val;

	// val = [ 1, -1, 2, -2, ... , 35, -35 ]
	if (iter % 2) {
		val = -(abs_val);
	} else {
		val = abs_val;
	}

	// Byte add
	byte_add(buf, pos, val);

	// if edited outside of buf, extend buf's size.
	if (pos >= size) {
		size = pos + 1;
	}

	return size;
}

/* populates fuzzing_strategy structure */
void
det_byte_arith_populate(fuzzing_strategy *strategy)
{
	strategy->version          = VERSION_ONE;
	strategy->name             = "det_byte_arith";
	strategy->create_state     = strategy_state_create;
	strategy->mutate           = det_byte_arith;
	strategy->serialize        = det_byte_arith_serialize;
	strategy->deserialize      = strategy_state_deserialize;
	strategy->print_state      = det_byte_arith_print;
	strategy->copy_state       = strategy_state_copy;
	strategy->free_state       = strategy_state_free;
	strategy->description      = "Deterministically adds a number to a byte. "
	                             "This strategy iterates through the range {-MAX_ARITH, MAX_ARITH}. "
	                             "MAX_ARITH is defined in afl_config.h. "
	                             "It adds a single value from the range, depending on the iteration number. "
	                             "Once it is done iterating through the range, it moves to the next byte in the buffer and repeats.";
	strategy->update_state     = strategy_state_update;
	strategy->is_deterministic = true;
}
