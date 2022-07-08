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

#include "afl_dictionary.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "afl.h"
#include "afl_config.h"
#include "afl_dictionary_insert.h"
#include "afl_dictionary_overwrite.h"
#include "common/yaml_helper.h"
#include "strategy.h"
#include "openssl/md5.h"

#ifdef AFL_DICTIONARY_IS_MASTER
get_fuzzing_strategy_function get_fuzzing_strategy = afl_dictionary_populate;
#endif

static FILE* log_file; 
static unsigned char md5_result[MD5_DIGEST_LENGTH]; 
static bool do_logging = false;

static void write_md5_sum(unsigned char* md, FILE* fp) { 
    int i;
    for (i = 0; i < MD5_DIGEST_LENGTH;  i++) { 
        fprintf(fp, "%02x", md[i]); 
        printf( "%02x", md[i]); 
    }
    fprintf(fp, "\n"); 
    printf( "\n"); 
}


// This function updates an afl_dictionary strategy_state object.
// it skips substrategy states that may not exist.
static inline void
afl_dictionary_update(strategy_state *state)
{
	afl_dictionary_substates *substates = (afl_dictionary_substates *)state->internal_state;

	if (substates->substrategy_complete) {
		substates->current_substrategy++;
		substates->substrategy_complete = 0;
	}
	// substrategy is not complete
	else {
		switch (substates->current_substrategy) {

		case USER_DICTIONARY_OVERWRITE: {
			// if substate exists, update its state
			if (substates->user_overwrite_substate) {
				substates->overwrite_strategy->update_state(substates->user_overwrite_substate);
			} else {
				// skip to the next substrategy
				substates->substrategy_complete = 1;
				afl_dictionary_update(state);
			}
			break;
		}
		case USER_DICTIONARY_INSERT: {
			// if substate exists, update its state
			if (substates->user_insert_substate) {
				substates->insert_strategy->update_state(substates->user_insert_substate);
			} else {
				// skip to the next substrategy
				substates->substrategy_complete = 1;
				afl_dictionary_update(state);
			}
			break;
		}
		case AUTO_DICTIONARY_OVERWRITE: {
			// if substate exists, update its state
			if (substates->auto_overwrite_substate) {
				substates->auto_overwrite_strategy->update_state(substates->auto_overwrite_substate);
			} else {
				// skip to the next substrategy
				substates->substrategy_complete = 1;
				afl_dictionary_update(state);
			}
			break;
		}
		default:
			break;
		}
	}
	state->iteration++;
}

// Serialize a state into a string!
static inline char *
afl_dictionary_serialize(strategy_state *state)
{
	afl_dictionary_substates *substates = (afl_dictionary_substates *)state->internal_state;

	// pointers to serialized structures
	char *s_state                   = NULL;
	char *s_substrategy_header      = NULL;
	char *s_user_overwrite_substate = NULL;
	char *s_user_insert_substate    = NULL;
	char *s_auto_overwrite_substate = NULL;
	char *s_afl_dictionary_state    = NULL;

	yaml_serializer *helper;
	size_t           total_size;
	size_t           mybuffersize;

	// First, serialize the topmost dictionary state structure
	s_state    = strategy_state_serialize(state, "afl_dictionary");
	total_size = strlen(s_state);

	// serialize current_strategy header
	helper = yaml_serializer_init("");
	YAML_SERIALIZE_8HEX_KV(helper, current_substrategy, substates->current_substrategy)
	YAML_SERIALIZE_8HEX_KV(helper, substrategy_complete, substates->substrategy_complete)
	yaml_serializer_end(helper, &s_substrategy_header, &mybuffersize);
	total_size += mybuffersize;

	// if substates exist, serialize them.
	if (substates->user_overwrite_substate) {
		s_user_overwrite_substate = substates->overwrite_strategy->serialize(substates->user_overwrite_substate);
		total_size += strlen(s_user_overwrite_substate);
	}
	if (substates->user_insert_substate) {
		s_user_insert_substate = substates->insert_strategy->serialize(substates->user_insert_substate);
		total_size += strlen(s_user_insert_substate);
	}
	if (substates->auto_overwrite_substate) {
		s_auto_overwrite_substate = substates->overwrite_strategy->serialize(substates->auto_overwrite_substate);
		total_size += strlen(s_auto_overwrite_substate);
	}

	// alloc a chunk to hold everything, +1 to null terminate the string
	s_afl_dictionary_state = calloc(1, total_size + 1);

	// concatenate all.
	strcat(s_afl_dictionary_state, s_state);
	strcat(s_afl_dictionary_state, s_substrategy_header);
	if (s_user_overwrite_substate)
		strcat(s_afl_dictionary_state, s_user_overwrite_substate);
	if (s_user_insert_substate)
		strcat(s_afl_dictionary_state, s_user_insert_substate);
	if (s_auto_overwrite_substate)
		strcat(s_afl_dictionary_state, s_auto_overwrite_substate);

	// free these old chunks
	free(s_state);
	free(s_substrategy_header);

	// free chunks for substates that were serialized.
	if (substates->user_overwrite_substate) {
		free(s_user_overwrite_substate);
	}
	if (substates->user_insert_substate) {
		free(s_user_insert_substate);
	}
	if (substates->auto_overwrite_substate) {
		free(s_auto_overwrite_substate);
	}

	// return the final result
	return s_afl_dictionary_state;
}

// deserialize an afl_dictionary strategy state.
static inline strategy_state *
afl_dictionary_deserialize(char *serialized_state, size_t serialized_state_size)
{
	// create new state object and substates object
	strategy_state           *new_state;
	afl_dictionary_substates *new_substates = calloc(1, sizeof(afl_dictionary_substates));

	// strategy objects, exposes API of substrategies.
	new_substates->overwrite_strategy = calloc(1, sizeof(fuzzing_strategy));
	new_substates->insert_strategy    = calloc(1, sizeof(fuzzing_strategy));
	new_state                         = strategy_state_deserialize(serialized_state, serialized_state_size);

	// deserialize substates header
	yaml_deserializer *helper;
	char              *s_substrategy_header = strstr(serialized_state, "...") + 4;

	helper = yaml_deserializer_init(NULL, s_substrategy_header, serialized_state_size - (size_t)(s_substrategy_header - serialized_state));

	// Get to the document start
	YAML_DESERIALIZE_PARSE(helper)
	while (helper->event.type != YAML_DOCUMENT_START_EVENT) {
		YAML_DESERIALIZE_EAT(helper)
	}

	YAML_DESERIALIZE_EAT(helper)
	YAML_DESERIALIZE_GET_KV_U8(helper, "current_substrategy", &new_substates->current_substrategy)
	YAML_DESERIALIZE_GET_KV_U8(helper, "substrategy_complete", &new_substates->substrategy_complete)

	// Prevent leaking memory
	YAML_DESERIALIZE_EVENT_DELETE(helper)

	yaml_deserializer_end(helper);

	// Loop on deserializing states that follow the initial strategy_state and substate_header belonging to afl_dictionary.
	// Since serialized substates are not manditory, we identify which of three types by the serialized strategy_name.

	char *serialized_substrategy;

	for (serialized_substrategy = strstr(s_substrategy_header, "...") + 4;
	     serialized_substrategy != (void *)4;
	     serialized_substrategy = strstr(serialized_substrategy, "...") + 4) {

		char substrategy_name[40];

		// We ignore cases where a strategy_name is not seen as that is probably part of a dictionary paired with the preceeding strategy.
		if (sscanf(serialized_substrategy, "---\nstrategy_name: %s", substrategy_name) == 1) {

			if (strcmp(substrategy_name, "afl_dictionary_overwrite") == 0) {

				afl_dictionary_overwrite_populate(new_substates->overwrite_strategy);
				new_substates->user_overwrite_substate = new_substates->overwrite_strategy->deserialize(serialized_substrategy, serialized_state_size - (size_t)(serialized_substrategy - serialized_state));

			} else if (strcmp(substrategy_name, "afl_dictionary_insert") == 0) {

				afl_dictionary_insert_populate(new_substates->insert_strategy);
				new_substates->user_insert_substate = new_substates->insert_strategy->deserialize(serialized_substrategy, serialized_state_size - (size_t)(serialized_substrategy - serialized_state));

			} else if (strcmp(substrategy_name, "afl_dictionary_auto_overwrite") == 0) {

				afl_dictionary_insert_populate(new_substates->auto_overwrite_strategy);
				new_substates->auto_overwrite_substate = new_substates->auto_overwrite_strategy->deserialize(serialized_substrategy, serialized_state_size - (size_t)(serialized_substrategy - serialized_state));

			} else {

				fprintf(stderr, "\nUnknown serialized strategy %s seen.\n\n", serialized_substrategy);
			}
		}
	}

	// fixup internal_state pointer.
	new_state->internal_state = new_substates;

	return new_state;
}

// print a afl_dictionary strategy state
static inline char *
afl_dictionary_print(strategy_state *state)
{
	afl_dictionary_substates *substates = (afl_dictionary_substates *)state->internal_state;

	// pointers to serialized fields
	// deserialize will use "X" to denote a nonexistent substate.
	char *p_user_overwrite_substate = NULL;
	char *p_user_insert_substate    = NULL;
	char *p_auto_overwrite_substate = NULL;
	char *p_current_substrategy     = NULL;
	char *p_substrategy_complete    = NULL;
	char *p_state                   = strategy_state_print(state, "afl_dictionary");
	char *p_afl_dictionary_state    = NULL;
	int   retval                    = 0;
	// size of the final string that is returned.
	size_t total_size = 0;

	retval = asprintf(&p_current_substrategy, "Current Substrategy: %02u\n", substates->current_substrategy);
	if (retval < 0) {
		fprintf(stderr, "asprintf failed near line %d\n", __LINE__);
	}

	retval = asprintf(&p_substrategy_complete, "Substrategy Complete: %02u\n", substates->substrategy_complete);
	if (retval < 0) {
		fprintf(stderr, "asprintf failed near line %d\n", __LINE__);
	}

	total_size += strlen(p_state) + strlen(p_current_substrategy) + strlen(p_substrategy_complete);

	// if substates exist, serialize them.
	if (substates->user_overwrite_substate) {
		p_user_overwrite_substate = substates->overwrite_strategy->print_state(substates->user_overwrite_substate);
		total_size += strlen(p_user_overwrite_substate);
	}

	if (substates->user_insert_substate) {
		p_user_insert_substate = substates->insert_strategy->print_state(substates->user_insert_substate);
		total_size += strlen(p_user_insert_substate);
	}

	if (substates->auto_overwrite_substate) {
		p_auto_overwrite_substate = substates->auto_overwrite_strategy->print_state(substates->auto_overwrite_substate);
		total_size += strlen(p_auto_overwrite_substate);
	}
	// alloc a chunk to hold everything, +1 to null terminate the string
	p_afl_dictionary_state = calloc(1, total_size + 1);

	// concatenate all.
	strcat(p_afl_dictionary_state, p_state);
	strcat(p_afl_dictionary_state, p_current_substrategy);
	strcat(p_afl_dictionary_state, p_substrategy_complete);

	// free these old chunks
	free(p_state);
	free(p_current_substrategy);
	free(p_substrategy_complete);

	if (substates->user_overwrite_substate) {
		strcat(p_afl_dictionary_state, p_user_overwrite_substate);
		free(p_user_overwrite_substate);
	}
	if (substates->user_insert_substate) {
		strcat(p_afl_dictionary_state, p_user_insert_substate);
		free(p_user_insert_substate);
	}
	if (substates->auto_overwrite_substate) {
		strcat(p_afl_dictionary_state, p_auto_overwrite_substate);
		free(p_auto_overwrite_substate);
	}

	// return the final result
	return p_afl_dictionary_state;
}

// copy a afl_dictionary strategy state.
static inline strategy_state *
afl_dictionary_copy(strategy_state *state)
{
	afl_dictionary_substates *substates = (afl_dictionary_substates *)state->internal_state;

	strategy_state           *copy_state     = strategy_state_copy(state);
	afl_dictionary_substates *copy_substates = calloc(1, sizeof(afl_dictionary_substates));

	copy_substates->current_substrategy  = substates->current_substrategy;
	copy_substates->substrategy_complete = substates->substrategy_complete;

	// strategy objects, exposes API of substrategies.
	copy_substates->overwrite_strategy = calloc(1, sizeof(fuzzing_strategy));
	copy_substates->insert_strategy    = calloc(1, sizeof(fuzzing_strategy));

	// fill in substrategies
	afl_dictionary_overwrite_populate(copy_substates->overwrite_strategy);
	afl_dictionary_insert_populate(copy_substates->insert_strategy);

	// copy substates if they exist.
	if (substates->user_overwrite_substate) {
		copy_substates->user_overwrite_substate = substates->overwrite_strategy->copy_state(substates->user_overwrite_substate);
	}
	if (substates->user_insert_substate) {
		copy_substates->user_insert_substate = substates->insert_strategy->copy_state(substates->user_insert_substate);
	}
	if (substates->auto_overwrite_substate) {
		copy_substates->auto_overwrite_substate = substates->auto_overwrite_strategy->copy_state(substates->auto_overwrite_substate);
	}
	copy_state->internal_state = copy_substates;

	return copy_state;
}

// free an afl_dictionary strategy state.
static inline void
afl_dictionary_free(strategy_state *state)
{
    if (do_logging) {
        fclose(log_file);
    }
	afl_dictionary_substates *substates = (afl_dictionary_substates *)state->internal_state;

	if (substates->user_overwrite_substate) {
		substates->overwrite_strategy->free_state(substates->user_overwrite_substate);
	}
	if (substates->user_insert_substate) {
		substates->insert_strategy->free_state(substates->user_insert_substate);
	}
	if (substates->auto_overwrite_substate) {
		substates->overwrite_strategy->free_state(substates->auto_overwrite_substate);
	}
	free(substates->overwrite_strategy);
	free(substates->insert_strategy);

	// free the substate object
	free(substates);

	state->internal_state = NULL;
	strategy_state_free(state);
}

static inline strategy_state *
afl_dictionary_create(u8 *seed, size_t max_size, size_t size, u8 *orig_buff, ...)
{
	printf("AFL DICTIONARY CREATE: size: %lu\n", size);
	strategy_state           *new_state     = strategy_state_create(seed, max_size, size, orig_buff);
	afl_dictionary_substates *new_substates = calloc(1, sizeof(afl_dictionary_substates));
	// get path to files describing dictionaries to use.
	char *user_dict_file = getenv("USER_DICTIONARY_FILE");
        printf("user_dict_file: %s\n", user_dict_file); 
	char *auto_dict_file = getenv("AUTO_DICTIONARY_FILE");

	// strategy objects, exposes API of substrategies.
	new_substates->overwrite_strategy = calloc(1, sizeof(fuzzing_strategy));
	new_substates->insert_strategy    = calloc(1, sizeof(fuzzing_strategy));

	// fill in objects
	afl_dictionary_overwrite_populate(new_substates->overwrite_strategy);
	afl_dictionary_insert_populate(new_substates->insert_strategy);

	if (user_dict_file) {
		// set starting substrategy to user_dictionary_overwrite
		new_substates->current_substrategy = USER_DICTIONARY_OVERWRITE;

		new_substates->user_overwrite_substate = new_substates->overwrite_strategy->create_state(seed, max_size, size, orig_buff, user_dict_file, MAX_USER_DICT_ENTRIES, MAX_USER_DICT_ENTRY_LEN);
		new_substates->user_insert_substate    = new_substates->insert_strategy->create_state(seed, max_size, size, orig_buff, user_dict_file);
	}
	if (auto_dict_file) {
		// if starting substrategy is not set, set it to auto_dictionary_overwrite
		if (!new_substates->current_substrategy) {
			new_substates->current_substrategy = AUTO_DICTIONARY_OVERWRITE;
		}
		new_substates->auto_overwrite_substate = new_substates->auto_overwrite_strategy->create_state(seed, max_size, size, orig_buff, auto_dict_file, MAX_AUTO_DICT_ENTRIES, MAX_AUTO_DICT_ENTRY_LEN);
	}
	// if no user_dict file and no auto_dict file, set current substrategy
	// to u8 max, skipping all strategies in the mutate function.
	if (!new_substates->current_substrategy) {
		new_substates->current_substrategy = 0xff;
	}
	new_state->internal_state = new_substates;

        char* env_log_file = getenv("LOG_FILE"); 
        if (env_log_file != NULL) { 
            do_logging = true;
            log_file = fopen(env_log_file, "a"); 
            if (!log_file) 
                log_fatal("Fopen failed"); 
        }

	return new_state;
}

// do the mutation, returns 0 when complete.
static inline size_t
afl_dictionary(u8 *buf, size_t size, strategy_state *state)
{
	afl_dictionary_substates *substates    = (afl_dictionary_substates *)state->internal_state;
	size_t                    results_size = 0;
        char*                     stage_name = NULL; 
        printf("current substrategy: %d\n", substates->current_substrategy);

	switch (substates->current_substrategy) {
	case USER_DICTIONARY_OVERWRITE: {
		if (substates->user_overwrite_substate) {
                        stage_name = "user extras (over) "; 
			results_size = substates->overwrite_strategy->mutate(buf, size, substates->user_overwrite_substate);
		}
		// if substate doesn't exist or is done
		if (!results_size) {
			// skip to the next substrategy
			substates->substrategy_complete = 1;
			afl_dictionary_update(state);
			// mutate.
			results_size = afl_dictionary(buf, size, state);
		}
		break;
	}
	case USER_DICTIONARY_INSERT: {
		if (substates->user_insert_substate) {
                        stage_name = "user extras (insert) "; 
			results_size = substates->insert_strategy->mutate(buf, size, substates->user_insert_substate);
		}
		// if substate doesn't exist or is done
		if (!results_size) {
			// skip to the next substrategy
			substates->substrategy_complete = 1;
			afl_dictionary_update(state);
			// mutate.
			results_size = afl_dictionary(buf, size, state);
		}
		break;
	}
	case AUTO_DICTIONARY_OVERWRITE: {
		if (substates->auto_overwrite_substate) {
                        stage_name = "auto extras (over) "; 
			results_size = substates->auto_overwrite_strategy->mutate(buf, size, substates->auto_overwrite_substate);
		}
		// if substate doesn't exist or is done
		if (!results_size) {
			// skip to the next substrategy
			substates->substrategy_complete = 1;
		}
		break;
	}
	default:
                stage_name = "default ";
		break;
	}

            MD5((unsigned char*) buf, results_size, md5_result);
            printf("stage_name: %s, out_buf: %s\n", stage_name, buf);
            write_md5_sum(md5_result, log_file); 
            printf("results_size: %zu\n", results_size); 
        //if (do_logging && stage_name) {
            //fwrite(stage_name, sizeof(char), strlen(stage_name), log_file); 
            //MD5((unsigned char*) buf, size, md5_result);
            //write_md5_sum(md5_result, log_file); 
        //}
	return results_size;
}

/* populates fuzzing_strategy structure */
void
afl_dictionary_populate(fuzzing_strategy *strategy)
{
	strategy->version          = VERSION_ONE;
	strategy->name             = "afl_dictionary";
	strategy->create_state     = afl_dictionary_create;
	strategy->mutate           = afl_dictionary;
	strategy->serialize        = afl_dictionary_serialize;
	strategy->deserialize      = afl_dictionary_deserialize;
	strategy->print_state      = afl_dictionary_print;
	strategy->copy_state       = afl_dictionary_copy;
	strategy->free_state       = afl_dictionary_free;
	strategy->description      = "";
	strategy->update_state     = afl_dictionary_update;
	strategy->is_deterministic = true;
}
