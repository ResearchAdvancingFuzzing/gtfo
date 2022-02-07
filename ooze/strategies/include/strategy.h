#ifndef STRATEGY_H
#define STRATEGY_H

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

#pragma once
#include <stddef.h>

#include "common/types.h"
#include "ooze.h"

/*
    These functions are used to manipulate common strategy_state objects (defined in ooze.h).
*/

// These macro wraps the strategy_state_print/serialize functions.
// We do this so that the fuzzing_strategy->print_state/serialize function pointers
// only need to take one argument.

#define PRINT_FUNC(func_name, strategy_name)               \
	static inline char *                                   \
	func_name(strategy_state *state)                       \
	{                                                      \
		return strategy_state_print(state, strategy_name); \
	}

#define SERIALIZE_FUNC(func_name, strategy_name)               \
	static inline char *                                       \
	func_name(strategy_state *state)                           \
	{                                                          \
		return strategy_state_serialize(state, strategy_name); \
	}

strategy_state *strategy_state_copy(strategy_state *state);
void            strategy_state_free(strategy_state *state);
char           *strategy_state_serialize(strategy_state *state, char *name);
strategy_state *strategy_state_deserialize(char *s_state_buffer, size_t s_state_buffer_size);
char           *strategy_state_print(strategy_state *state, char *strategy_name);
void            strategy_state_update(strategy_state *state);
strategy_state *strategy_state_create(u8 *seed, size_t max_size, ...);

#endif
