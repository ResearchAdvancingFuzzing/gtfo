#ifndef AFL_ARITH_H
#define AFL_ARITH_H

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
#include "afl.h"
#include "common/types.h"
#include "det_byte_arith.h"
#include "det_four_byte_arith_be.h"
#include "det_four_byte_arith_le.h"
#include "det_two_byte_arith_be.h"
#include "det_two_byte_arith_le.h"
#include "ooze.h"

typedef struct afl_arith_substates {

	u8   current_substrategy;
	u8   substrategy_complete;
	char pad[sizeof(void(*)(void)) - sizeof(u8) * 2];
	// strategy_state for each substrategy
	strategy_state *det_byte_arith_substate;
	strategy_state *det_two_byte_arith_le_substate;
	strategy_state *det_two_byte_arith_be_substate;
	strategy_state *det_four_byte_arith_le_substate;
	strategy_state *det_four_byte_arith_be_substate;
	// fuzzing_strategy object for each substrategy,
	// provides access to each strategy's api.
	fuzzing_strategy *det_byte_arith_strategy;
	fuzzing_strategy *det_two_byte_arith_le_strategy;
	fuzzing_strategy *det_two_byte_arith_be_strategy;
	fuzzing_strategy *det_four_byte_arith_le_strategy;
	fuzzing_strategy *det_four_byte_arith_be_strategy;

} afl_arith_substates;

void afl_arith_populate(fuzzing_strategy *strategy);

#endif
