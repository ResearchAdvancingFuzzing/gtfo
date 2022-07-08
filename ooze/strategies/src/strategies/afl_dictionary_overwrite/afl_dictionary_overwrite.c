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

#include "afl_dictionary_overwrite.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "common/types.h"
#include "dictionary.h"
#include "strategy.h"

#ifdef AFL_DICTIONARY_OVERWRITE_IS_MASTER
get_fuzzing_strategy_function get_fuzzing_strategy = afl_dictionary_overwrite_populate;
#endif

// serialize a state into a string!
static inline char *
afl_dictionary_overwrite_serialize(strategy_state *state)
{
	// serialize the state, and the dictionary
	char *serialized_state = strategy_state_serialize(state, "afl_dictionary_overwrite");
	char *serialized_dict  = dictionary_serialize((dictionary *)state->internal_state);

	// get their serialized lengths
	size_t s_state_len = strlen(serialized_state);
	size_t s_dict_len  = strlen(serialized_dict);

	// new buf to hold both of the serialized bufs
	char *serialized_all = calloc(1, s_state_len + s_dict_len + 1);

	// copy in serialized state and serialized dict
	strcat(serialized_all, serialized_state);
	strcat(serialized_all, serialized_dict);

	// free old bufs
	free(serialized_state);
	free(serialized_dict);

	return serialized_all;
}

// deserialize a strategy state
static inline strategy_state *
afl_dictionary_overwrite_deserialize(char *serialized_state, size_t serialized_state_size)
{
	// get ptrs to serialized state and serialized dict
	char *s_dict = strstr(serialized_state, "...") + 4;

	strategy_state *state = strategy_state_deserialize(serialized_state, serialized_state_size);
	dictionary     *dict  = dictionary_deserialize(s_dict, serialized_state_size - (size_t)(s_dict - serialized_state));

	state->internal_state = dict;

	return state;
}

// print a state
static inline char *
afl_dictionary_overwrite_print(strategy_state *state)
{
	dictionary *dict          = (dictionary *)state->internal_state;
	char       *printed_state = strategy_state_print(state, "afl_dictionary_overwrite");
	char       *printed_dict  = dictionary_print(dict);
	char       *printed_both  = calloc(1, strlen(printed_state) + strlen(printed_dict) + 1);
	strcat(printed_both, printed_state);
	strcat(printed_both, printed_dict);

	free(printed_state);
	free(printed_dict);

	return printed_both;
}

static inline strategy_state *
afl_dictionary_overwrite_copy(strategy_state *state)
{
	// copy everything from the strategy state
	strategy_state *new_state = calloc(1, sizeof(strategy_state));
	memcpy(new_state, state, sizeof(strategy_state));

	new_state->internal_state = dictionary_copy((dictionary *)state->internal_state);

	return new_state;
}
// free a state, untested
static inline void
afl_dictionary_overwrite_free(strategy_state *state)
{
	dictionary_free((dictionary *)state->internal_state);
	state->internal_state = NULL;
	strategy_state_free(state);
}

static inline strategy_state *
afl_dictionary_overwrite_create(u8 *seed, size_t max_size, size_t size, u8 *orig_buff, ...)
{
	va_list va_l;
	va_start(va_l, orig_buff);

	char  *dictionary_file_path = va_arg(va_l, char *);
	size_t max_entry_cnt        = va_arg(va_l, size_t);
	size_t max_token_len        = va_arg(va_l, size_t);

	va_end(va_l);

	strategy_state *new_state = strategy_state_create(seed, max_size, size, orig_buff);
	new_state->internal_state = dictionary_load_file(dictionary_file_path, max_entry_cnt, max_token_len);

	return new_state;
}

// do the mutation
#pragma clang diagnostic ignored "-Wunreachable-code"
static inline size_t
afl_dictionary_overwrite(u8 *buf, size_t size, strategy_state *state)
{

	dictionary       *dict  = (dictionary *)state->internal_state;
	u32               pos   = (u32)(state->iteration / dict->entry_cnt);
	u32               which = (u32)(state->iteration % dict->entry_cnt);
	dictionary_entry *entry = (*dict->entries)[which];
	
        // Sometimes we need to skip, we've added 1/4 ways to skip
		printf("Dict entry size: %lu, replace pos: %u, orig_size: %lu\n", entry->len, pos, state->size);
        while (entry->len > size - pos) {
            // This is update state, need a way to update better
            state->iteration++; 
            dict  = (dictionary *)state->internal_state;
            pos = (u32) (state->iteration / dict->entry_cnt); 
            which = (u32) (state->iteration % dict->entry_cnt); 
            entry = (*dict->entries)[which]; 
            
            // this is deterministic and shouldn't go on infinitely?
	    	if (pos  >= state->size || dict->entry_cnt == 0) {
            	printf("here_overwrite");
				return 0;
			}
        }
/*
	    printf("state->iteration: %lu, dict->entry_cnt: %zu\n", state->iteration, dict->entry_cnt);
	    printf("pos: %u, entry len: %lu, size: %lu, max_size: %lu, which: %u\n", pos, entry->len, state->max_size, state->size, which);
*/
	    if (pos >= state->max_size || dict->entry_cnt == 0) {
			return 0;
		}
		/*
        printf("out_buf_before: %.*s, ", (int) size, buf);
        printf("adding: %.*s, ", (int) entry->len, entry->token); 
        printf(" at i: %d, ", pos); 
		*/

	// copy the token
	memcpy(buf + pos, entry->token, entry->len);
    //printf("out_buf_after: %s\n", buf); 

	// update size if necessary.
	if (pos + entry->len > size) {
		size = pos + entry->len;
	}
	return size;
}

/* populates fuzzing_strategy structure */
void
afl_dictionary_overwrite_populate(fuzzing_strategy *strategy)
{
	strategy->version          = VERSION_ONE;
	strategy->name             = "afl_dictionary_overwrite";
	strategy->create_state     = afl_dictionary_overwrite_create;
	strategy->mutate           = afl_dictionary_overwrite;
	strategy->serialize        = afl_dictionary_overwrite_serialize;
	strategy->deserialize      = afl_dictionary_overwrite_deserialize;
	strategy->print_state      = afl_dictionary_overwrite_print;
	strategy->copy_state       = afl_dictionary_overwrite_copy;
	strategy->free_state       = afl_dictionary_overwrite_free;
	strategy->description      = "";
	strategy->update_state     = strategy_state_update;
	strategy->is_deterministic = true;
}
