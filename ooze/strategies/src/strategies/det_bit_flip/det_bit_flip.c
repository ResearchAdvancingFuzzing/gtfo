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

#include "det_bit_flip.h"

#include "mutate.h"
#include "strategy.h"

SERIALIZE_FUNC(det_bit_flip_serialize, "det_bit_flip")
PRINT_FUNC(det_bit_flip_print, "det_bit_flip")

#ifdef DET_BIT_FLIP_IS_MASTER
get_fuzzing_strategy_function get_fuzzing_strategy = det_bit_flip_populate;
#endif

static inline size_t
det_bit_flip(u8 *buf, size_t size, strategy_state *state)
{
	// going to edit bits outside of max size.
	if ((state->iteration >= (state->max_size * CHAR_BIT))) {
		return 0;
	}

	bit_flip(buf, state->iteration);

	// if edited outside of buf, extend buf's size.
	if (state->iteration >= (size * CHAR_BIT)) {
		size++;
	}
	return size;
}

/* populates fuzzing_strategy structure */
void
det_bit_flip_populate(fuzzing_strategy *strategy)
{
	strategy->version          = VERSION_ONE;
	strategy->name             = "det_bit_flip";
	strategy->create_state     = strategy_state_create;
	strategy->mutate           = det_bit_flip;
	strategy->serialize        = det_bit_flip_serialize;
	strategy->deserialize      = strategy_state_deserialize;
	strategy->print_state      = det_bit_flip_print;
	strategy->copy_state       = strategy_state_copy;
	strategy->free_state       = strategy_state_free;
	strategy->description      = "On the first iteration it flips the first bit, and so on...";
	strategy->update_state     = strategy_state_update;
	strategy->is_deterministic = true;
}
