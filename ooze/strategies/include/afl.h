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
#include "afl_config.h"
#include "prng.h"
#include "common/types.h"

/*
	This file holds afl-related options and functions that should not be touched.
*/

/* Fuzzing stages */
enum {
	/* 00 */ BIT_FLIP,
	/* 01 */ TWO_BIT_FLIP,
	/* 02 */ FOUR_BIT_FLIP,
	/* 03 */ BYTE_FLIP,
	/* 04 */ TWO_BYTE_FLIP,
	/* 05 */ FOUR_BYTE_FLIP,
	/* 06 */ BYTE_ARITH,
	/* 07 */ TWO_BYTE_ARITH_LE,
	/* 08 */ TWO_BYTE_ARITH_BE,
	/* 09 */ FOUR_BYTE_ARITH_LE,
	/* 10 */ FOUR_BYTE_ARITH_BE,
	/* 11 */ BYTE_INTERESTING,
	/* 12 */ TWO_BYTE_INTERESTING_LE,
	/* 13 */ TWO_BYTE_INTERESTING_BE,
	/* 14 */ FOUR_BYTE_INTERESTING_LE,
	/* 15 */ FOUR_BYTE_INTERESTING_BE,
	/* 16 */ USER_DICTIONARY_OVERWRITE,
	/* 17 */ USER_DICTIONARY_INSERT,
	/* 18 */ AUTO_DICTIONARY_OVERWRITE,
	/* 19 */ HAVOC,
	/* 20 */ SPLICE

};

// substrategies that compose the afl strategy.
enum {
	/* 00 */ AFL_BIT_FLIP,
	/* 01 */ AFL_ARITH,
	/* 02 */ AFL_INTERESTING,
	/* 03 */ AFL_DICTIONARY,
	/* 04 */ AFL_HAVOC,
	/* 05 */ AFL_SPLICE
};

u64 afl_choose_block_len(prng_state *prng_state, u64 limit);
u8 could_be_bitflip(u32 xor_val);
u8 could_be_arith(u32 old_val, u32 new_val, u8 blen);
u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le);
