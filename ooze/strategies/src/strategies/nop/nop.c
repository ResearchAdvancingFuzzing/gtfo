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

#include "nop.h"

#include "strategy.h"

SERIALIZE_FUNC(nop_serialize, "nop")
PRINT_FUNC(nop_print, "nop")

#ifdef NOP_IS_MASTER
get_fuzzing_strategy_function get_fuzzing_strategy = nop_populate;
#endif

// Does nothing
static inline size_t
nop_strategy(__attribute__((unused)) u8 *buf, size_t size, __attribute__((unused)) strategy_state *state)
{
	return size;
}

/* populates fuzzing_strategy structure */
void
nop_populate(fuzzing_strategy *strategy)
{
	strategy->version          = VERSION_ONE;
	strategy->name             = "nop_strategy";
	strategy->create_state     = strategy_state_create;
	strategy->mutate           = nop_strategy;
	strategy->serialize        = nop_serialize;
	strategy->deserialize      = strategy_state_deserialize;
	strategy->print_state      = nop_print;
	strategy->copy_state       = strategy_state_copy;
	strategy->free_state       = strategy_state_free;
	strategy->description      = "Does not modify the input (for testing only)";
	strategy->update_state     = strategy_state_update;
	strategy->is_deterministic = false;
}
