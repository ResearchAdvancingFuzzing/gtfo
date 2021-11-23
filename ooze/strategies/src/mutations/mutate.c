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

#include "mutate.h"

#include <stdlib.h>
#include <string.h>

#include "afl_config.h"

// Globals used by the 'interesting' mutations and strategies.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-statement-expression"
#pragma clang diagnostic ignored "-Wcast-align"

s8  interesting_8[]  = {INTERESTING_8};
s16 interesting_16[] = {INTERESTING_8, INTERESTING_16};
s32 interesting_32[] = {INTERESTING_8, INTERESTING_16, INTERESTING_32};

#define INTERESTING_8_ELEMENTS 9
#define INTERESTING_16_ELEMENTS 19
#define INTERESTING_32_ELEMENTS 27
/*
	This function flips the bit at offset 'bit_pos' in buffer 'buf'.
*/
inline void
bit_flip(u8 *buf, u64 bit_pos)
{
	FLIP_BIT(buf, bit_pos);
}

/*
	This function flips two bits at offset 'bit_pos' in buffer 'buf'.
*/
inline void
two_bit_flip(u8 *buf, u64 bit_pos)
{
	FLIP_BIT(buf, bit_pos);
	FLIP_BIT(buf, bit_pos + 1);
}

/*
	This function flips four bits at offset 'bit_pos' in buffer 'buf'.
*/
inline void
four_bit_flip(u8 *buf, u64 bit_pos)
{
	two_bit_flip(buf, bit_pos);
	two_bit_flip(buf, bit_pos + 2);
}

/*
	This function flips 'n' bits in buffer 'buf', starting at offset 'bit_pos'.
*/
inline void
n_bit_flip(u8 *buf, u64 bit_pos, u64 n)
{
	u64 i = 0;
	for (; i < n; i++) {
		FLIP_BIT(buf, bit_pos + i);
	}
}

/*
	This function flips every bit of the byte at offset 'pos' in buffer 'buf'.
*/
inline void
byte_flip(u8 *buf, size_t pos)
{
	buf[pos] ^= (u8)0xFF;
}

/*
	This function flips the two bytes at offset 'pos' in buffer 'buf'.
*/
inline void
two_byte_flip(u8 *buf, size_t pos)
{
	byte_flip(buf, pos);
	byte_flip(buf, pos + 1);
}

/*
	This function flips the four bytes at offset 'pos' in buffer 'buf'.
*/
inline void
four_byte_flip(u8 *buf, size_t pos)
{
	byte_flip(buf, pos);
	byte_flip(buf, pos + 1);
	byte_flip(buf, pos + 2);
	byte_flip(buf, pos + 3);
}

/*
	This function flips the eight bytes at offset 'pos' in buffer 'buf'.
*/
inline void
eight_byte_flip(u8 *buf, size_t pos)
{
	byte_flip(buf, pos);
	byte_flip(buf, pos + 1);
	byte_flip(buf, pos + 2);
	byte_flip(buf, pos + 3);
	byte_flip(buf, pos + 4);
	byte_flip(buf, pos + 5);
	byte_flip(buf, pos + 6);
	byte_flip(buf, pos + 7);
}

/*
	This function flips n bytes, starting at at offset 'pos' in buffer 'buf'.
*/
inline void
n_byte_flip(u8 *buf, size_t pos, u64 n)
{

	u64 i = 0;

	for (; i < n; i++) {
		byte_flip(buf, pos + n);
	}
}

/*
	This function increments the byte at offset 'pos' in buffer 'buf'.
*/
inline void
byte_inc(u8 *buf, u64 pos)
{
	buf[pos]++;
}

/*
	This function increments the two bytes at offset 'pos' in the buffer 'buf'.

	Little-endian.
*/

inline void
two_byte_inc_le(u8 *buf, u64 pos)
{
	u16 *foo = (u16 *)&buf[pos];
	*foo     = SWAP16(*foo);
	*foo     = SWAP16(*foo + 1);
}
/*
 	This function increments the four bytes at offset 'pos' in the buffer 'buf'.

 	Little-endian.
*/
inline void
four_byte_inc_le(u8 *buf, u64 pos)
{
	u32 *foo = (u32 *)&buf[pos];
	*foo     = SWAP32(*foo);
	*foo     = SWAP32(*foo + 1);
}

/*
	This function increments the eight bytes at offset 'pos' in the buffer 'buf'.

	Little-endian.
*/
inline void
eight_byte_inc_le(u8 *buf, u64 pos)
{
	u64 *foo = (u64 *)&buf[pos];
	*foo     = SWAP64(*foo);
	*foo     = SWAP64(*foo + 1);
}

/*
	This function increments the two bytes at offset 'pos' in the buffer 'buf'.

	Big-endian.
*/
inline void
two_byte_inc_be(u8 *buf, u64 pos)
{
	u16 *foo = (u16 *)&buf[pos];
	*foo     = (u16) (*foo + 1);
}

/*
 	This function increments the four bytes at offset 'pos' in the buffer 'buf'.

 	Big-endian.
*/
inline void
four_byte_inc_be(u8 *buf, u64 pos)
{
	u32 *foo = (u32 *)&buf[pos];
	*foo     = *foo + 1;
}

/*
	This function increments the eight bytes at offset 'pos' in the buffer 'buf'.

	Big-endian.
*/
inline void
eight_byte_inc_be(u8 *buf, u64 pos)
{
	u64 *foo = (u64 *)&buf[pos];
	*foo     = *foo + 1;
}

/*
 	This function decrements the byte at offset 'pos' in the buffer 'buf'.
*/
inline void
byte_dec(u8 *buf, u64 pos)
{
	buf[pos]--;
}

/*
 	This function decrements the two bytes at offset 'pos' in the buffer 'buf'.

 	Little-endian.
*/
inline void
two_byte_dec_le(u8 *buf, u64 pos)
{
	u16 *foo = (u16 *)&buf[pos];
	*foo     = SWAP16(*foo);
	*foo     = SWAP16(*foo - 1);
}

/*
 	This function decrements the four bytes at offset 'pos' in the buffer 'buf'.

 	Little-endian.
*/
inline void
four_byte_dec_le(u8 *buf, u64 pos)
{
	u32 *foo = (u32 *)&buf[pos];
	*foo     = SWAP32(*foo);
	*foo     = SWAP32(*foo - 1);
}

/*
 	This function decrements the eight bytes at offset 'pos' in the buffer 'buf'.

 	Little-endian.
*/
inline void
eight_byte_dec_le(u8 *buf, u64 pos)
{
	u64 *foo = (u64 *)&buf[pos];
	*foo     = SWAP64(*foo);
	*foo     = SWAP64(*foo - 1);
}

/*
 	This function decrements the two bytes at offset 'pos' in the buffer 'buf'.

 	Big-endian.
*/
inline void
two_byte_dec_be(u8 *buf, u64 pos)
{
	u16 *foo = (u16 *)&buf[pos];
	*foo     = (u16)(*foo - 1);
}

/*
 	This function decrements the four bytes at offset 'pos' in the buffer 'buf'.

 	Big-endian.
*/
inline void
four_byte_dec_be(u8 *buf, u64 pos)
{
	u32 *foo = (u32 *)&buf[pos];
	*foo     = *foo - 1;
}

/*
 	This function decrements the eight bytes at offset 'pos' in the buffer 'buf'.

 	Big-endian.
*/
inline void
eight_byte_dec_be(u8 *buf, u64 pos)
{
	u64 *foo = (u64 *)&buf[pos];
	*foo     = *foo - 1;
}

/*
 	This function adds value 'val' to the byte at offset 'pos' in buffer 'buf'.
*/
inline void
byte_add(u8 *buf, u64 pos, u8 val)
{
	buf[pos] += val;
}

/*
 	This function adds value 'val' to the two bytes at offset 'pos' in buffer 'buf'.

 	Little-endian.
*/
inline void
two_byte_add_be(u8 *buf, u64 pos, u16 val)
{
	u16 *foo = (u16 *)&buf[pos];
	*foo     = SWAP16(*foo);
	*foo     = SWAP16(*foo + val);
}

/*
 	This function adds value 'val' to the four bytes at offset 'pos' in buffer 'buf'.

 	Little-endian.
*/
inline void
four_byte_add_be(u8 *buf, u64 pos, u32 val)
{
	u32 *foo = (u32 *)&buf[pos];
	*foo     = SWAP32(*foo);
	*foo     = SWAP32(*foo + val);
}

/*
 	This function adds value 'val' to the eight bytes at offset 'pos' in buffer 'buf'.

 	Little-endian.
*/
inline void
eight_byte_add_le(u8 *buf, u64 pos, u64 val)
{
	u64 *foo = (u64 *)&buf[pos];
	*foo     = SWAP64(*foo);
	*foo     = SWAP64(*foo + val);
}

/*
 	This function adds value 'val' to the two bytes at offset 'pos' in buffer 'buf'.

 	Big-endian.
*/
inline void
two_byte_add_le(u8 *buf, u64 pos, u16 val)
{
	u16 *foo = (u16 *)&buf[pos];
	*foo     = *foo + val;
}

/*
 	This function adds value 'val' to the four bytes at offset 'pos' in buffer 'buf'.

 	Big-endian.
*/
inline void
four_byte_add_le(u8 *buf, u64 pos, u32 val)
{
	u32 *foo = (u32 *)&buf[pos];
	*foo     = *foo + val;
}

/*
 	This function adds value 'val' to the eight bytes at offset 'pos' in buffer 'buf'.

 	Big-endian.
*/
inline void
eight_byte_add_be(u8 *buf, u64 pos, u64 val)
{
	u64 *foo = (u64 *)&buf[pos];
	*foo     = *foo + val;
}

/*
	This function removes a byte at offset 'pos' from a buffer 'buf' of length 'len'.
*/
inline void
byte_drop(u8 *buf, size_t len, u64 pos)
{
	memmove(&buf[pos], &buf[pos + 1], len - (pos + 1));
}

/*
	This function removes two bytes at offset 'pos' from a buffer 'buf' of length 'len'.
*/
inline void
two_byte_drop(u8 *buf, size_t len, u64 pos)
{
	memmove(&buf[pos], &buf[pos + 2], len - (pos + 2));
}

/*
	This function removes four bytes at offset 'pos' from a buffer 'buf' of length 'len'.
*/
inline void
four_byte_drop(u8 *buf, size_t len, u64 pos)
{
	memmove(&buf[pos], &buf[pos + 4], len - (pos + 4));
}

/*
	This function removes eight bytes at offset 'pos' from a buffer 'buf' of length 'len'.
*/
inline void
eight_byte_drop(u8 *buf, size_t len, u64 pos)
{
	memmove(&buf[pos], &buf[pos + 8], len - (pos + 8));
}

/*
	This function removes 'n' bytes at offset 'pos' from a buffer 'buf' of length 'len'.
*/
inline void
n_byte_drop(u8 *buf, size_t len, u64 pos, u64 n)
{
	u64 i = 0;
	for (; i < n; i++) {
		byte_drop(buf, len, pos + i);
	}
}

/*
	This function swaps the byte at 'byte1_pos' with the byte at 'byte2_pos' in buffer 'buf'.
*/
inline void
byte_swap(u8 *buf, __attribute__((unused)) size_t size, u64 byte1_pos, u64 byte2_pos)
{
	u8 tmp         = buf[byte1_pos];
	buf[byte1_pos] = buf[byte2_pos];
	buf[byte2_pos] = tmp;
}

/*
	This function swaps the two bytes at 'byte1_pos' with the byte at 'byte2_pos' in buffer 'buf'.
*/
inline void
two_byte_swap(u8 *buf, __attribute__((unused)) size_t size, u64 byte1_pos, u64 byte2_pos)
{
	u16 *foo = (u16 *)&buf[byte1_pos];
	u16 *bar = (u16 *)&buf[byte2_pos];
	u16  tmp = *foo;

	*foo = *bar;
	*bar = tmp;
}

/*
	This function swaps the four bytes at 'byte1_pos' with the byte at 'byte2_pos' in buffer 'buf'.
*/
inline void
four_byte_swap(u8 *buf, __attribute__((unused)) size_t size, u64 byte1_pos, u64 byte2_pos)
{
	u32 *foo = (u32 *)&buf[byte1_pos];
	u32 *bar = (u32 *)&buf[byte2_pos];
	u32  tmp = *foo;

	*foo = *bar;
	*bar = tmp;
}

/*
	This function swaps the eight bytes at 'byte1_pos' with the byte at 'byte2_pos' in buffer 'buf'.
*/
inline void
eight_byte_swap(u8 *buf, __attribute__((unused)) size_t size, u64 byte1_pos, u64 byte2_pos)
{
	u64 *foo = (u64 *)&buf[byte1_pos];
	u64 *bar = (u64 *)&buf[byte2_pos];
	u64  tmp = *foo;

	*foo = *bar;
	*bar = tmp;
}

/*
	This function swaps 'n' bytes at 'byte1_pos' with n bytes at 'byte2_pos' in buffer 'buf'.
*/
inline void
n_byte_swap(u8 *buf, size_t size, u64 byte1_pos, u64 byte2_pos, u64 n)
{
	u64 i = 0;
	for (; i < n; i++) {
		byte_swap(buf, size, byte1_pos + i, byte2_pos + i);
	}
}

/*
	This function repeats the byte at position 'pos' in buffer 'buf' 'num_repeat' times.

	ie. ABCD -> ABBBBBBCD.
*/
inline void
byte_inplace_repeat(u8 *buf, size_t size, u64 pos, u64 num_repeat)
{
	u8 byte = buf[pos];

	memcpy(buf + pos + num_repeat, buf + pos, size - pos - num_repeat);
	memset(buf + pos, byte, num_repeat);
}

/*
 	This function replaces the byte at offset 'pos' in buffer 'buf' with the byte 'replacement'.
*/
inline void
byte_replace(u8 *buf, __attribute__((unused)) size_t size, u64 pos, u8 replacement)
{
	buf[pos] = replacement;
}

/*
 	This function replaces the two bytes at offset 'pos' in buffer 'buf' with the bytes 'replacement'.
*/
inline void
two_byte_replace(u8 *buf, __attribute__((unused)) size_t size, size_t pos, u16 replacement)
{
	buf[pos]     = (u8)(replacement >> 8);
	buf[pos + 1] = (u8)((replacement << 8) >> 8);
}

/*
 	This function replaces the four bytes at offset 'pos' in buffer 'buf' with the bytes 'replacement'.
*/
inline void
four_byte_replace(u8 *buf, __attribute__((unused)) size_t size, size_t pos, u32 replacement)
{
	buf[pos]     = (u8)(replacement >> 24);
	buf[pos + 1] = (u8)((replacement << 8) >> 24);
	buf[pos + 2] = (u8)((replacement << 16) >> 24);
	buf[pos + 3] = (u8)((replacement << 24) >> 24);
}

/*
 	This function replaces the eight bytes at offset 'pos' in buffer 'buf' with the bytes 'replacement'.
*/
inline void
eight_byte_replace(u8 *buf, __attribute__((unused)) size_t size, size_t pos, u64 replacement)
{
	buf[pos]     = (u8)(replacement >> 56);
	buf[pos + 1] = (u8)((replacement << 8) >> 56);
	buf[pos + 2] = (u8)((replacement << 16) >> 56);
	buf[pos + 3] = (u8)((replacement << 24) >> 56);
	buf[pos + 4] = (u8)((replacement << 32) >> 56);
	buf[pos + 5] = (u8)((replacement << 40) >> 56);
	buf[pos + 6] = (u8)((replacement << 48) >> 56);
	buf[pos + 7] = (u8)((replacement << 56) >> 56);
}

/*
 	This function replaces 'n' bytes at offset 'pos' in buffer 'buf' with bytes from the buffer 'new_bytes'.
*/
inline void
n_byte_replace(u8 *buf, __attribute__((unused)) size_t size, size_t pos, u8 *new_bytes, size_t n)
{
	memcpy(buf + pos, new_bytes, n);
}

/*
	This function repeats 'n' bytes at position 'pos' in buffer 'buf'.

	ie. ABCD -> ABCBCD.

		pos: 1
		n: 2
			memmove step: 	ABCD -> A__BCD
			memcpy step:	A__BCD -> ABCBCD
*/
inline void
n_byte_inplace_repeat(u8 *buf, size_t size, size_t pos, size_t n)
{
	memmove(buf + pos + n, buf + pos, size - pos);
	memcpy(buf + pos, buf + pos + n, n);
}

/*
 	This function inserts a single byte into the buffer 'buf' at offset 'pos'.
*/
inline void
byte_ins(u8 *buf, size_t size, u64 pos, u8 byte)
{
	memmove(buf + pos + 1, buf + pos, size - pos);
	byte_replace(buf, size, pos, byte);
}

/*
 	This function inserts two bytes into the buffer at offset 'pos'.
*/
inline void
two_byte_ins(u8 *buf, size_t size, u64 pos, u16 two_bytes)
{
	memmove(buf + pos + 2, buf + pos, size - pos);
	two_byte_replace(buf, size, pos, two_bytes);
}
/*
 	This function inserts four bytes into the buffer at offset 'pos'.
*/
inline void
four_byte_ins(u8 *buf, size_t size, u64 pos, u32 four_bytes)
{
	memmove(buf + pos + 4, buf + pos, size - pos);
	four_byte_replace(buf, size, pos, four_bytes);
}

/*
 	This function inserts eight bytes into the buffer at offset 'pos'.
*/
inline void
eight_byte_ins(u8 *buf, size_t size, u64 pos, u64 eight_bytes)
{
	memmove(buf + pos + 8, buf + pos, size - pos);
	eight_byte_replace(buf, size, pos, eight_bytes);
}

/*
 	This function inserts 'n' bytes from string 'bytes' into the buffer at offset 'pos'.
*/
inline void
n_byte_ins(u8 *buf, size_t size, u64 pos, u8 *bytes, size_t n)
{
	memmove(buf + pos + n, buf + pos, size - pos);
	n_byte_replace(buf, size, pos, bytes, n);
}

/*
 	This function replaces a byte at offset 'pos' in buffer 'buf'
 	with one of the 8-bit interesting values.
*/
inline void
byte_interesting(u8 *buf, u64 pos, u8 which)
{
	buf[pos] = (u8)interesting_8[which % INTERESTING_8_ELEMENTS];
}

/*
 	This function replaces a byte at offset 'pos' in buffer 'buf'
 	with one of the 8-bit or 16-bit interesting values.

 	Little-endian.
*/
inline void
two_byte_interesting_be(u8 *buf, u64 pos, u8 which)
{
	u16 *foo = (u16 *)&buf[pos];
	*foo     = (u16)SWAP16(*foo);
	*foo     = (u16)SWAP16((u16)interesting_16[which % INTERESTING_16_ELEMENTS]);
}

/*
 	This function replaces a byte at offset 'pos' in buffer 'buf'
 	with one of the 8-bit, 16-bit, or 32-bit interesting values.

 	Little-endian.
*/
inline void
four_byte_interesting_be(u8 *buf, u64 pos, u8 which)
{
	u32 *foo = (u32 *)&buf[pos];
	*foo     = (u32)SWAP32(*foo);
	*foo     = (u32)SWAP32((u32)interesting_32[which % INTERESTING_32_ELEMENTS]);
}

/*
 	This function replaces a byte at offset 'pos' in buffer 'buf'
 	with one of the 8-bit, 16-bit, or 32-bit interesting values.

 	Big-endian.
*/
inline void
two_byte_interesting_le(u8 *buf, u64 pos, u8 which)
{
	u16 *foo = (u16 *)&buf[pos];
	*foo     = (u16)interesting_16[which % INTERESTING_16_ELEMENTS];
}

/*
 	This function replaces a byte at offset 'pos' in buffer 'buf'
 	with one of the 8-bit, 16-bit, or 32-bit interesting values.

 	Big-endian.
*/
inline void
four_byte_interesting_le(u8 *buf, u64 pos, u8 which)
{
	u32 *foo = (u32 *)&buf[pos];
	*foo     = (u32)interesting_32[which % INTERESTING_32_ELEMENTS];
}

/*
	This function copies n bytes from buf + src_offset and insert them at buf+dest_offset.
*/
inline void
n_byte_copy_and_ins(u8 *buf, size_t size, size_t src_offset, size_t dest_offset, size_t n)
{
	u8 *copy_chunk = calloc(1, n);
	memcpy(copy_chunk, buf + src_offset, n);

	n_byte_ins(buf, size, dest_offset, copy_chunk, n);

	free(copy_chunk);
}

/*
	This function removes n bytes at buf + pos and concatenates what's left.
*/
inline void
n_byte_delete(u8 *buf, size_t size, size_t pos, size_t n)
{
	memmove(buf + pos, buf + pos + n, size - (pos + n));
}
#pragma clang diagnostic pop
#pragma GCC diagnostic pop
