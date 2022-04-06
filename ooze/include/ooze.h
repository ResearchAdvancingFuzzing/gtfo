#ifndef OOZE_H
#define OOZE_H

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
#include "common.h"
#include <assert.h>
#include <ctype.h> // for qsort
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define VERSION_ONE 1

// This is the standard strategy state object, used by every strategy to maintain state information.
// strategies/src/strategy.c contains methods that operate on a strategy_state.

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
	// An optional pointer to an additional data structure required by the strategy.
	// ex: dictionary_insert maintains a dictionary object, the pointer to that object goes here.
	void *internal_state;
} strategy_state;

typedef strategy_state *(create_state)(u8 *seed, size_t max_size, size_t size, ...);
typedef size_t(fuzz_function)(u8 *buffer, size_t size, strategy_state *state);
typedef char *(serialize_state)(strategy_state *state);
typedef strategy_state *(deserialize_state)(char *s_state_buffer, size_t state_buffer_size);
typedef char *(print_state)(strategy_state *state);
typedef strategy_state *(copy_state)(strategy_state *state);
typedef void(free_state)(strategy_state *state);
typedef void(update_state)(strategy_state *state);

// This structure represents a fuzzing strategy.
// It provides a uniform API for each strategy library.
typedef struct fuzzing_strategy {

	// Version number of this strategy.
	int  version;
	char pad0[sizeof(void(*)(void)) - sizeof(int)];
	union {
		// version one
		struct {
			// The name of the fuzzing strategy.
			const char *name;

			// Function to perform any initialization required by the strategy.
			create_state *create_state;
			// Function to perform a single mutation using the provided strategy.
			fuzz_function *mutate;
			// Function to serialize a strategy_state into an ascii bytestring.
			serialize_state *serialize;
			// Function to deserialize an ascii bytestring into a strategy_state.
			deserialize_state *deserialize;
			// Debug function to print information about a strategy_state.
			print_state *print_state;
			// Function to make a copy of a strategy_state
			copy_state *copy_state;
			// Function to free a strategy_state
			free_state *free_state;
			// Function to update a strategy_state
			update_state *update_state;

			// Whether or not the fuzzing strategy is deterministic
			bool is_deterministic;
			char pad1[sizeof(void(*)(void)) - sizeof(char)];

			// A description of the fuzzing strategy
			const char *description;
		};
	};
} fuzzing_strategy;

typedef void (*get_fuzzing_strategy_function)(fuzzing_strategy *strategy);

// For a given strategy library, this function pointer points to the function that populates the fuzzing_strategy object.
extern __attribute__((visibility("default"))) get_fuzzing_strategy_function get_fuzzing_strategy;

#endif
