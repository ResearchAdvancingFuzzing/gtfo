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

#include "det_two_byte_ins.h"

#include "common/types.h"
#include "mutate.h"
#include "strategy.h"

SERIALIZE_FUNC(det_two_byte_ins_serialize, "det_two_byte_ins")
PRINT_FUNC(det_two_byte_ins_print, "det_two_byte_ins")

#ifdef DET_TWO_BYTE_INS_IS_MASTER
get_fuzzing_strategy_function get_fuzzing_strategy = det_two_byte_ins_populate;
#endif

static inline size_t
det_two_byte_ins(u8 *buf, size_t size, strategy_state *state)
{
	u16 byte = (u16)(state->iteration % 65536);
	u64 pos  = state->iteration / 65536;

	if (size + 2 > state->max_size || pos + 2 > state->max_size) {
		return 0;
	}

	two_byte_ins(buf, size, pos, byte);

	return size + 2;
}

/* populates fuzzing_strategy structure */
void
det_two_byte_ins_populate(fuzzing_strategy *strategy)
{
	strategy->version      = VERSION_ONE;
	strategy->name         = "det_two_byte_ins";
	strategy->create_state = strategy_state_create;
	strategy->mutate       = det_two_byte_ins;
	strategy->serialize    = det_two_byte_ins_serialize;
	strategy->deserialize  = strategy_state_deserialize;
	strategy->print_state  = det_two_byte_ins_print;
	strategy->copy_state   = strategy_state_copy;
	strategy->free_state   = strategy_state_free;
	strategy->description  = "Deterministically inserts two bytes. "
	                        "On the first iteration it inserts byte 0x0000 at position 0x0. "
	                        "On the next iteration, it inserts byte 0x0001 at position 0x0. "
	                        "This continues until all bytes have been inserted. "
	                        "It them moves to the next byte and repeats.";
	strategy->update_state     = strategy_state_update;
	strategy->is_deterministic = true;
}
