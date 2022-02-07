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
#include <bits/stdint-uintn.h>

#include "ooze.h"
#include "common/types.h"

// This object stores state information related to our prng.
typedef struct prng_state {
	// running prng state
	u64 state;
	// not sure, used by prng_state_update
	u64 inc;
} prng_state;

prng_state *prng_state_create(uint64_t new_state, u64 new_inc);
void        prng_state_update(prng_state *prng_st);
u32         prng_state_random(prng_state *prng_st);
void        prng_state_free(prng_state *prng_st);
prng_state *prng_state_copy(prng_state *prng_st);
char       *prng_state_serialize(prng_state *prng_st);
prng_state *prng_state_deserialize(char *s_state, size_t s_state_size);
char       *prng_state_print(prng_state *prng_st);
u64         prng_state_UR(prng_state *prng_state, u64 limit);
