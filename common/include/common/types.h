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
#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef enum {
	CRASH,
	NEW_SEED
} log_reason_t;

// Taken from AFL
#define STRINGIFY_INTERNAL(x) #x
#define STRINGIFY(x) STRINGIFY_INTERNAL(x)

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#ifndef MIN
#define MIN(_a, _b) ((_a) > (_b) ? (_b) : (_a))
#define MAX(_a, _b) ((_a) > (_b) ? (_a) : (_b))
#endif /* !MIN */

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
		u32 _bf  = (u32)(_b);                   \
		_arf[(_bf) >> (u8)3] ^= ((u8)128 >> ((_bf)&(u8)7)); \
	} while (0)
#endif
