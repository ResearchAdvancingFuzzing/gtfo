#ifndef COMMON_STRATEGY_STATE_H
#define COMMON_STRATEGY_STATE_H

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
#include "common/types.h"
#include "stdbool.h"

typedef struct strategy_state {
	// version number
	u64 version;
	// seed, may be used or not used.
	u8 seed[32];
	// the current iteration of input generation.
	u64 iteration;
	// the maximum size of input that the strategy can produce.
	size_t max_size;
    // the initial size of the input buffer 
    size_t size; 
	// the initial buffer
	u8 *orig_buff; 
	// An optional pointer to an additional data structure required by the strategy.
	// ex: dictionary_insert maintains a dictionary object, the pointer to that object goes here.
	void *internal_state;
} strategy_state;


#endif
