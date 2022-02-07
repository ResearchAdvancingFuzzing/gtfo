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

#include "det_two_byte_interesting_be.h"

#include "afl_config.h"
#include "common/types.h"
#include "mutate.h"
#include "strategy.h"

SERIALIZE_FUNC(det_two_byte_interesting_be_serialize, "det_two_byte_interesting_be")
PRINT_FUNC(det_two_byte_interesting_be_print, "det_two_byte_interesting_be")

#ifdef DET_TWO_BYTE_INTERESTING_BE_IS_MASTER
get_fuzzing_strategy_function get_fuzzing_strategy = det_two_byte_interesting_be_populate;
#endif

static inline size_t
det_two_byte_interesting_be(u8 *buf, size_t size, strategy_state *state)
{
	u8  interesting_val_count = INTERESTING_8_SIZE + INTERESTING_16_SIZE;
	u64 pos                   = state->iteration / interesting_val_count;

	if (pos + 2 > state->max_size) {
		return 0;
	}

	u8 which = (u8)(state->iteration % interesting_val_count);
	two_byte_interesting_be(buf, pos, which);
	if (pos + 2 > size) {
		size = pos + 2;
	}
	return size;
}

/* populates fuzzing_strategy structure */
void
det_two_byte_interesting_be_populate(fuzzing_strategy *strategy)
{
	strategy->version          = VERSION_ONE;
	strategy->name             = "det_two_byte_interesting_be";
	strategy->create_state     = strategy_state_create;
	strategy->mutate           = det_two_byte_interesting_be;
	strategy->serialize        = det_two_byte_interesting_be_serialize;
	strategy->deserialize      = strategy_state_deserialize;
	strategy->print_state      = det_two_byte_interesting_be_print;
	strategy->copy_state       = strategy_state_copy;
	strategy->free_state       = strategy_state_free;
	strategy->description      = "Deterministically replace two bytes with an interesting value. "
	                             "The endianness of the interesting value is switched to big-endian. "
	                             "This strategy iterates through the INTERESTING_8, and INTERESTING_16 values. "
	                             "INTERESTING_* is defined in afl_config.h. "
	                             "It replaces two bytes with a single value, depending on the iteration number. "
	                             "Once it is done iterating through the values, it moves to the next byte in the buffer and repeats.";
	strategy->update_state     = strategy_state_update;
	strategy->is_deterministic = true;
}
