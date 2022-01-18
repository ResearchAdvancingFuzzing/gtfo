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

#include "afl.h"

#include "afl_config.h"

/*
	This file holds afl-related functions.
*/

// This is a helper function to choose a 'block size'
// for data manipulation strategies.
inline u64
afl_choose_block_len(prng_state *prng_state, u64 limit)
{
	u64 min_value, max_value;

	// choose a block size
	switch (prng_state_UR(prng_state, 3)) {

	// 33 % chance of small block
	case 0:
		min_value = 1;
		max_value = HAVOC_BLK_SMALL;
		break;

	// 33% chance of medium block
	case 1:
		min_value = HAVOC_BLK_SMALL;
		max_value = HAVOC_BLK_MEDIUM;
		break;

	// 33% chance of a large block or xl block.
	default:

		if (prng_state_UR(prng_state, 2)) {

			min_value = HAVOC_BLK_MEDIUM;
			max_value = HAVOC_BLK_LARGE;

		} else {

			min_value = HAVOC_BLK_LARGE;
			max_value = HAVOC_BLK_XL;
		}
	}

	// ensure that the minimum block size is < our limit
	if (min_value >= limit)
		min_value = 1;

	// make sure that the maximum block size is smaller than our limit
	if (max_value > limit)
		max_value = limit;

	// randomly choose a block size in the range {min_value, max_value};
	return min_value + prng_state_UR(prng_state, max_value - min_value + 1);
}

inline u8 could_be_bitflip(u32 xor_val) {

	u32 sh = 0;
	if (!xor_val) return 1;

	/* Shift left until first bit set. */
	while (!(xor_val & 1)) { sh++; xor_val >>= 1; }

	/* 1-, 2-, and 4-bit patterns are OK anywhere. */
	if (xor_val == 1 || xor_val == 3 || xor_val == 15) return 1;

	/* 8-, 16-, and 32-bit patterns are OK only if shift factor is
	   divisible by 8, since that's the stepover for these ops. */
	if (sh & 7) return 0;
	if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff)
		return 1;

	return 0;
}
