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

#include <string.h>

#include "sage_test.h"
#include "strategy.h"

SERIALIZE_FUNC(sage_test_serialize, "sage_test")
PRINT_FUNC(sage_test_print, "sage_test")

#ifdef SAGE_TEST_IS_MASTER
get_fuzzing_strategy_function get_fuzzing_strategy = sage_test_populate;
#endif

static inline size_t
sage_mut(u8 *buf, size_t size, strategy_state *state)
{
	char *i0 = "good";
	char *i1 = "bood";
	char *i2 = "baod";
	char *i3 = "bad!";

	if (size < 4) {
		return 0;
	}

	if (state->max_size < strlen("bad!")) {
		return 0;
	}

	switch (state->iteration) {
	case 0:
	case 1:
		memcpy(buf, i0, 4);
		return 4;
	case 2:
	case 3:
		memcpy(buf, i1, 4);
		return 4;
	case 4:
	case 5:
		memcpy(buf, i2, 4);
		return 4;
	case 6:
	case 7:
		memcpy(buf, i3, 4);
		return 4;
	case 8:
	case 9:
		memcpy(buf, i2, 4);
		return 4;
	default:
		return 0;
	}
}

/* populates fuzzing_strategy structure */
void
sage_test_populate(fuzzing_strategy *strategy)
{
	strategy->version          = VERSION_ONE;
	strategy->name             = "sage_test";
	strategy->create_state     = strategy_state_create;
	strategy->mutate           = sage_mut;
	strategy->serialize        = sage_test_serialize;
	strategy->deserialize      = strategy_state_deserialize;
	strategy->print_state      = sage_test_print;
	strategy->copy_state       = strategy_state_copy;
	strategy->free_state       = strategy_state_free;
	strategy->description      = "This is for the sage test.";
	strategy->update_state     = strategy_state_update;
	strategy->is_deterministic = true;
}
