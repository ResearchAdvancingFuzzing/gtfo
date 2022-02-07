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

#include "det_four_byte_inc_le.h"

#include "common/types.h"
#include "mutate.h"
#include "strategy.h"

SERIALIZE_FUNC(det_four_byte_inc_le_serialize, "det_four_byte_inc_le")
PRINT_FUNC(det_four_byte_inc_le_print, "det_four_byte_inc_le")

#ifdef DET_FOUR_BYTE_INC_LE_IS_MASTER
get_fuzzing_strategy_function get_fuzzing_strategy = det_four_byte_inc_le_populate;
#endif

static inline size_t
det_four_byte_inc_le(u8 *buf, size_t size, strategy_state *state)
{
	// position of byte to mutate
	u64 pos = state->iteration;

	// if position points out of the max size, we're done
	if (pos + 4 > state->max_size) {
		return 0;
	}
	// else decrement byte
	four_byte_inc_le(buf, pos);

	if (pos + 4 > size) {
		size = pos + 4;
	}

	return size;
}

/* populates fuzzing_strategy structure */
void
det_four_byte_inc_le_populate(fuzzing_strategy *strategy)
{
	strategy->version          = VERSION_ONE;
	strategy->name             = "det_four_byte_inc_le";
	strategy->create_state     = strategy_state_create;
	strategy->mutate           = det_four_byte_inc_le;
	strategy->serialize        = det_four_byte_inc_le_serialize;
	strategy->deserialize      = strategy_state_deserialize;
	strategy->print_state      = det_four_byte_inc_le_print;
	strategy->copy_state       = strategy_state_copy;
	strategy->free_state       = strategy_state_free;
	strategy->description      = "Deterministically increments four bytes in the buffer. "
	                             "The four bytes in question are treated as a single little-endian integer. "
	                             "it moves forward a single byte position in the buffer and repeats.";
	strategy->update_state     = strategy_state_update;
	strategy->is_deterministic = true;
}
