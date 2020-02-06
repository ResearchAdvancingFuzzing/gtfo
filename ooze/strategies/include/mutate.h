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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "afl_config.h"
#include "ooze.h"
#include "common/types.h"

#define SWAP16(_x) ({                     \
	u16 _ret = (_x);                  \
	(u16)((_ret << 8) | (_ret >> 8)); \
})

#define SWAP32(_x) ({                       \
	u32 _ret = (_x);                    \
	(u32)((_ret << 24) | (_ret >> 24) | \
	      ((_ret << 8) & 0x00FF0000) |  \
	      ((_ret >> 8) & 0x0000FF00));  \
})

#define SWAP64(_x)                            \
	(((u64)SWAP32((u32)((_x)&0xffffffff)) \
	  << 32) |                            \
	 (u64)SWAP32((u32)((_x) >> 32)))

#ifndef FLIP_BIT
#define FLIP_BIT(_ar, _b)                               \
	do {                                            \
		u8 *_arf = (u8 *)(_ar);                 \
		u64 _bf  = (_b);                        \
		_arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
	} while (0)
#endif

extern s8  interesting_8[];
extern s16 interesting_16[];
extern s32 interesting_32[];

/*
	Prototypes for all existing mutations.
*/
void bit_flip(u8 *buf, u64 bit_pos);
void two_bit_flip(u8 *buf, u64 bit_pos);
void four_bit_flip(u8 *buf, u64 bit_pos);
void n_bit_flip(u8 *buf, u64 bit_pos, u64 n);

void byte_flip(u8 *buf, size_t pos);
void two_byte_flip(u8 *buf, size_t pos);
void four_byte_flip(u8 *buf, size_t pos);
void eight_byte_flip(u8 *buf, size_t pos);
void n_byte_flip(u8 *buf, size_t pos, u64 n);

void byte_inc(u8 *buf, u64 pos);

void two_byte_inc_le(u8 *buf, u64 pos);
void four_byte_inc_le(u8 *buf, u64 pos);
void eight_byte_inc_le(u8 *buf, u64 pos);

void two_byte_inc_be(u8 *buf, u64 pos);
void four_byte_inc_be(u8 *buf, u64 pos);
void eight_byte_inc_be(u8 *buf, u64 pos);

void byte_dec(u8 *buf, u64 pos);

void two_byte_dec_le(u8 *buf, u64 pos);
void four_byte_dec_le(u8 *buf, u64 pos);
void eight_byte_dec_le(u8 *buf, u64 pos);

void two_byte_dec_be(u8 *buf, u64 pos);
void four_byte_dec_be(u8 *buf, u64 pos);
void eight_byte_dec_be(u8 *buf, u64 pos);

void byte_add(u8 *buf, u64 pos, u8 val);

void two_byte_add_le(u8 *buf, u64 pos, u16 val);
void four_byte_add_le(u8 *buf, u64 pos, u32 val);
void eight_byte_add_le(u8 *buf, u64 pos, u64 val);

void two_byte_add_be(u8 *buf, u64 pos, u16 val);
void four_byte_add_be(u8 *buf, u64 pos, u32 val);
void eight_byte_add_be(u8 *buf, u64 pos, u64 val);

void byte_drop(u8 *buf, size_t len, u64 pos);
void two_byte_drop(u8 *buf, size_t len, u64 pos);
void four_byte_drop(u8 *buf, size_t len, u64 pos);
void eight_byte_drop(u8 *buf, size_t len, u64 pos);
void n_byte_drop(u8 *buf, size_t len, u64 pos, u64 n);

void byte_swap(u8 *buf, __attribute__((unused)) size_t size, u64 byte1_pos, u64 byte2_pos);
void two_byte_swap(u8 *buf, __attribute__((unused)) size_t size, u64 byte1_pos, u64 byte2_pos);
void four_byte_swap(u8 *buf, __attribute__((unused)) size_t size, u64 byte1_pos, u64 byte2_pos);
void eight_byte_swap(u8 *buf, __attribute__((unused)) size_t size, u64 byte1_pos, u64 byte2_pos);
void n_byte_swap(u8 *buf, __attribute__((unused)) size_t size, u64 byte1_pos, u64 byte2_pos, u64 n);

void byte_inplace_repeat(u8 *buf, size_t size, u64 pos, u64 num_repeat);
void n_byte_inplace_repeat(u8 *buf, size_t size, size_t pos, size_t n);

void byte_replace(u8 *buf, __attribute__((unused)) size_t size, u64 pos, u8 replacement);
void two_byte_replace(u8 *buf, __attribute__((unused)) size_t size, size_t pos, u16 replacement);
void four_byte_replace(u8 *buf, __attribute__((unused)) size_t size, size_t pos, u32 replacement);
void eight_byte_replace(u8 *buf, __attribute__((unused)) size_t size, size_t pos, u64 replacement);
void n_byte_replace(u8 *buf, __attribute__((unused)) size_t size, size_t pos, u8 *new_bytes, size_t n);

void byte_ins(u8 *buf, size_t size, u64 pos, u8 byte);
void two_byte_ins(u8 *buf, size_t size, u64 pos, u16 two_bytes);
void four_byte_ins(u8 *buf, size_t size, u64 pos, u32 four_bytes);
void eight_byte_ins(u8 *buf, size_t size, u64 pos, u64 eight_bytes);
void n_byte_ins(u8 *buf, size_t size, u64 pos, u8 *bytes, size_t n);

void byte_interesting(u8 *buf, u64 pos, u8 which);

void two_byte_interesting_le(u8 *buf, u64 pos, u8 which);
void four_byte_interesting_le(u8 *buf, u64 pos, u8 which);

void two_byte_interesting_be(u8 *buf, u64 pos, u8 which);
void four_byte_interesting_be(u8 *buf, u64 pos, u8 which);

void n_byte_copy_and_ins(u8 *buf, size_t size, size_t src_offset, size_t dest_offset, size_t n);
void n_byte_delete(u8 *buf, size_t size, size_t pos, size_t n);
