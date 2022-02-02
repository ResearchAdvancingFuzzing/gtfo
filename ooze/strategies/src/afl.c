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

/* Helper function to see if a particular value is reachable through
   arithmetic operations. Used for similar purposes. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-statement-expression"
inline u8 could_be_arith(u32 old_val, u32 new_val, u8 blen) {

	u32 i, ov = 0, nv = 0, diffs = 0;

	if (old_val == new_val) return 1;

	/* See if one-byte adjustments to any byte could produce this result. */

	for (i = 0; i < blen; i++) {

		u8 a = (u8)(old_val >> (8 * i)),
		   b = (u8)(new_val >> (8 * i));

		if (a != b) { diffs++; ov = a; nv = b; }

	}

	/* If only one byte differs and the values are within range, return 1. */

	if (diffs == 1) {

		if ((u8)(ov - nv) <= MAX_ARITH ||
		    (u8)(nv - ov) <= MAX_ARITH) return 1;

	}

	if (blen == 1) return 0;

	/* See if two-byte adjustments to any byte would produce this result. */

	diffs = 0;

	for (i = 0; i < blen / 2; i++) {

		u16 a = (u16)(old_val >> (16 * i)),
		    b = (u16)(new_val >> (16 * i));

		if (a != b) { diffs++; ov = a; nv = b; }

	}

	/* If only one word differs and the values are within range, return 1. */

	if (diffs == 1) {

		if ((u16)(ov - nv) <= MAX_ARITH ||
		    (u16)(nv - ov) <= MAX_ARITH) return 1;

		ov = SWAP16((u16)ov); nv = SWAP16((u16)nv);

		if ((u16)(ov - nv) <= MAX_ARITH ||
		    (u16)(nv - ov) <= MAX_ARITH) return 1;

	}

	/* Finally, let's do the same thing for dwords. */

	if (blen == 4) {

		if ((u32)(old_val - new_val) <= MAX_ARITH ||
		    (u32)(new_val - old_val) <= MAX_ARITH) return 1;

		new_val = SWAP32(new_val);
		old_val = SWAP32(old_val);

		if ((u32)(old_val - new_val) <= MAX_ARITH ||
		    (u32)(new_val - old_val) <= MAX_ARITH) return 1;

	}

	return 0;

}

/* Last but not least, a similar helper to see if insertion of an
   interesting integer is redundant given the insertions done for
   shorter blen. The last param (check_le) is set if the caller
   already executed LE insertion for current blen and wants to see
   if BE variant passed in new_val is unique. */

#pragma clang diagnostic ignored "-Wsign-conversion"
inline u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le) {
	 s8  interesting_8[]  = { INTERESTING_8 };
	 s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
	 s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };

	u32 i, j;

	if (old_val == new_val) return 1;

	/* See if one-byte insertions from interesting_8 over old_val could
	   produce new_val. */

	for (i = 0; i < blen; i++) {

		for (j = 0; j < sizeof(interesting_8); j++) {

			u32 tval = (old_val & ~(0xff << (i * 8))) |
			           (((u8)(interesting_8[j])) << (i * 8));

			if (new_val == tval) return 1;

		}

	}

	/* Bail out unless we're also asked to examine two-byte LE insertions
	   as a preparation for BE attempts. */

	if (blen == 2 && !check_le) return 0;

	/* See if two-byte insertions over old_val could give us new_val. */

	for (i = 0; i < blen - 1; i++) {

		for (j = 0; j < sizeof(interesting_16) / 2; j++) {

			u32 tval = (old_val & ~(0xffff << (i * 8))) |
			           (((u16)interesting_16[j]) << (i * 8));

			if (new_val == tval) return 1;

			/* Continue here only if blen > 2. */

			if (blen > 2) {

				tval = (old_val & ~(0xffff << (i * 8))) |
				       (SWAP16(interesting_16[j]) << (i * 8));

				if (new_val == tval) return 1;

			}

		}

	}

	if (blen == 4 && check_le) {

		/* See if four-byte insertions could produce the same result
		   (LE only). */

		for (j = 0; j < sizeof(interesting_32) / 4; j++)
			if (new_val == (u32)interesting_32[j]) return 1;

	}

	return 0;

}
#pragma clang diagnostic pop
