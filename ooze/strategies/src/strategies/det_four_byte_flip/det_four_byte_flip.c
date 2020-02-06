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

#include "det_four_byte_flip.h"

#include "common/types.h"
#include "mutate.h"
#include "strategy.h"

SERIALIZE_FUNC(det_four_byte_flip_serialize, "det_four_byte_flip")
PRINT_FUNC(det_four_byte_flip_print, "det_four_byte_flip")

#ifdef DET_FOUR_BYTE_FLIP_IS_MASTER
get_fuzzing_strategy_function get_fuzzing_strategy = det_four_byte_flip_populate;
#endif

static inline size_t
det_four_byte_flip(u8 *buf, size_t size, strategy_state *state)
{
	u64 pos = state->iteration;

	if (pos + 4 > state->max_size) {
		return 0;
	}

	four_byte_flip(buf, pos);

	if (pos + 4 > size) {
		size = pos + 4;
	}

	return size;
}

/* populates fuzzing_strategy structure */
void
det_four_byte_flip_populate(fuzzing_strategy *strategy)
{
	strategy->version      = VERSION_ONE;
	strategy->name         = "det_four_byte_flip";
	strategy->create_state = strategy_state_create;
	strategy->mutate       = det_four_byte_flip;
	strategy->serialize    = det_four_byte_flip_serialize;
	strategy->deserialize  = strategy_state_deserialize;
	strategy->print_state  = det_four_byte_flip_print;
	strategy->copy_state   = strategy_state_copy;
	strategy->free_state   = strategy_state_free;
	strategy->description  = "On the first iteration it flips the four bytes at byte position 0. "
	                        "On the next iteration, it flips the four bytes at byte position 1. "
	                        "And so on and so forth etc etc etc...";
	strategy->update_state     = strategy_state_update;
	strategy->is_deterministic = true;
}
