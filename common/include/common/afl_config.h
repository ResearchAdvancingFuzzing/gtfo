#ifndef AFL_CONFIG_H
#define AFL_CONFIG_H

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

/*
    This file holds customizeable options that are used by afl-inspired strategies.
*/

#define INTERESTING_8                                      \
	-128,    /* Overflow signed 8-bit when decremented  */ \
	    -1,  /*                                         */ \
	    0,   /*                                         */ \
	    1,   /*                                         */ \
	    16,  /* One-off with common buffer size         */ \
	    32,  /* One-off with common buffer size         */ \
	    64,  /* One-off with common buffer size         */ \
	    100, /* One-off with common buffer size         */ \
	    127  /* Overflow signed 8-bit when incremented  */

#define INTERESTING_16                                      \
	-32768,   /* Overflow signed 16-bit when decremented */ \
	    -129, /* Overflow signed 8-bit                   */ \
	    128,  /* Overflow signed 8-bit                   */ \
	    255,  /* Overflow unsig 8-bit when incremented   */ \
	    256,  /* Overflow unsig 8-bit                    */ \
	    512,  /* One-off with common buffer size         */ \
	    1000, /* One-off with common buffer size         */ \
	    1024, /* One-off with common buffer size         */ \
	    4096, /* One-off with common buffer size         */ \
	    32767 /* Overflow signed 16-bit when incremented */

#define INTERESTING_32                                            \
	-2147483648LL,  /* Overflow signed 32-bit when decremented */ \
	    -100663046, /* Large negative number (endian-agnostic) */ \
	    -32769,     /* Overflow signed 16-bit                  */ \
	    32768,      /* Overflow signed 16-bit                  */ \
	    65535,      /* Overflow unsig 16-bit when incremented  */ \
	    65536,      /* Overflow unsig 16 bit                   */ \
	    100663045,  /* Large positive number (endian-agnostic) */ \
	    2147483647  /* Overflow signed 32-bit when incremented */

#define INTERESTING_8_SIZE 9
#define INTERESTING_16_SIZE 10
#define INTERESTING_32_SIZE 8

// maximum value used for *_arith* strategies.
#define MAX_ARITH 35

/* Maximum user dictionary token size, in bytes. */
#define MAX_USER_DICT_ENTRY_LEN 128

/* Maximum number of user-specified dictionary tokens to use.*/
#define MAX_USER_DICT_ENTRIES 200

/* Maximum auto dictionary token size, in bytes. */
#define MAX_AUTO_DICT_ENTRY_LEN 32

/* Maximum number of auto-extracted dictionary tokens to actually use in fuzzing
   (first value), and to keep in memory as candidates. The latter should be much
   higher than the former. */
#define USE_AUTO_DICT_ENTRIES 50
#define MAX_AUTO_DICT_ENTRIES (USE_AUTO_DICT_ENTRIES * 10)

/* Maximum stacking for havoc-stage tweaks. The actual value is calculated
   like this:

   n = random between 1 and HAVOC_STACK_POW2
   stacking = 2^n

   In other words, the default (n = 7) produces 2, 4, 8, 16, 32, 64, or
   128 stacked tweaks: */

#define HAVOC_STACK_POW2 7

/* Caps on block sizes for cloning and deletion operations. Each of these
   ranges has a 33% probability of getting picked, except for the first
   two cycles where smaller blocks are favored: */

#define HAVOC_BLK_SMALL 32
#define HAVOC_BLK_MEDIUM 128
#define HAVOC_BLK_LARGE 1500

/* Extra-large blocks, selected very rarely (<5% of the time): */

#define HAVOC_BLK_XL 32768

#define MAX_LINE 8192

#endif
