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

#include "afl_bit_flip.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "afl.h"
#include "common/yaml_helper.h"
#include "det_bit_flip.h"
#include "det_byte_flip.h"
#include "det_four_bit_flip.h"
#include "det_four_byte_flip.h"
#include "det_two_bit_flip.h"
#include "det_two_byte_flip.h"
#include "strategy.h"
#include "openssl/md5.h"

#ifdef AFL_BIT_FLIP_IS_MASTER
get_fuzzing_strategy_function get_fuzzing_strategy = afl_bit_flip_populate;
#endif

static FILE* log_file;
static unsigned char md5_result[MD5_DIGEST_LENGTH];
static bool do_logging = false;

static void write_md5_sum(unsigned char* md, FILE* fp) { 
    int i;
    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        fprintf(fp, "%02x", md[i]);
    }
    fprintf(fp, "\n");
} 


// this function updates the running states and substates
static inline void
afl_bit_flip_update(strategy_state *state)
{
	afl_bit_flip_substates *substates = (afl_bit_flip_substates *)state->internal_state;

	// if a substrategy was complete, move on to the next substrategy
	if (substates->substrategy_complete) {
		substates->current_substrategy++;
		substates->substrategy_complete = 0;
	} else {
		// update the correct substate
		switch (substates->current_substrategy) {

		case BIT_FLIP:
			substates->det_bit_flip_strategy->update_state(substates->det_bit_flip_substate);
			break;

		case TWO_BIT_FLIP:
			substates->det_two_bit_flip_strategy->update_state(substates->det_two_bit_flip_substate);
			break;

		case FOUR_BIT_FLIP:
			substates->det_four_bit_flip_strategy->update_state(substates->det_four_bit_flip_substate);
			break;

		case BYTE_FLIP:
			substates->det_byte_flip_strategy->update_state(substates->det_byte_flip_substate);
			break;

		case TWO_BYTE_FLIP:
			substates->det_two_byte_flip_strategy->update_state(substates->det_two_byte_flip_substate);
			break;

		case FOUR_BYTE_FLIP:
			substates->det_four_byte_flip_strategy->update_state(substates->det_four_byte_flip_substate);
			break;

		default:
			break;
		}
	}
	// update general purpose iterator
	state->iteration++;
}

// create an afl_bit_flip strategy_state object.
static inline strategy_state *
afl_bit_flip_create(u8 *seed, size_t max_size, ...)
{

	// create new state and substates objects
	strategy_state         *new_state = strategy_state_create(seed, max_size);
	afl_bit_flip_substates *substates = calloc(1, sizeof(afl_bit_flip_substates));

	// fill in substates
	substates->current_substrategy  = BIT_FLIP;
	substates->substrategy_complete = 0;

	// create empty fuzzing_strategy objects
	substates->det_bit_flip_strategy       = calloc(1, sizeof(fuzzing_strategy));
	substates->det_two_bit_flip_strategy   = calloc(1, sizeof(fuzzing_strategy));
	substates->det_four_bit_flip_strategy  = calloc(1, sizeof(fuzzing_strategy));
	substates->det_byte_flip_strategy      = calloc(1, sizeof(fuzzing_strategy));
	substates->det_two_byte_flip_strategy  = calloc(1, sizeof(fuzzing_strategy));
	substates->det_four_byte_flip_strategy = calloc(1, sizeof(fuzzing_strategy));

	// populate fuzzing_strategy objects
	det_bit_flip_populate(substates->det_bit_flip_strategy);
	det_two_bit_flip_populate(substates->det_two_bit_flip_strategy);
	det_four_bit_flip_populate(substates->det_four_bit_flip_strategy);
	det_byte_flip_populate(substates->det_byte_flip_strategy);
	det_two_byte_flip_populate(substates->det_two_byte_flip_strategy);
	det_four_byte_flip_populate(substates->det_four_byte_flip_strategy);

	// create substates
	substates->det_bit_flip_substate       = substates->det_bit_flip_strategy->create_state(seed, max_size);
	substates->det_two_bit_flip_substate   = substates->det_two_bit_flip_strategy->create_state(seed, max_size);
	substates->det_four_bit_flip_substate  = substates->det_four_bit_flip_strategy->create_state(seed, max_size);
	substates->det_byte_flip_substate      = substates->det_byte_flip_strategy->create_state(seed, max_size);
	substates->det_two_byte_flip_substate  = substates->det_two_byte_flip_strategy->create_state(seed, max_size);
	substates->det_four_byte_flip_substate = substates->det_four_byte_flip_strategy->create_state(seed, max_size);

	new_state->internal_state = substates;

        char* env_log_file = getenv("LOG_FILE"); 
        if (env_log_file != NULL) {
            do_logging = true; 
            log_file = fopen(env_log_file, "a"); 
            if (!log_file) 
                log_fatal("Fopen failed"); 
        }

	return new_state;
}

// this function serializes a strategy state object
static inline char *
afl_bit_flip_serialize(strategy_state *state)
{
	afl_bit_flip_substates *substates = (afl_bit_flip_substates *)state->internal_state;

	// serialize all of the strategy states
	char *s_state                       = NULL;
	char *s_substrategy_header          = NULL;
	char *s_det_bit_flip_substate       = substates->det_bit_flip_strategy->serialize(substates->det_bit_flip_substate);
	char *s_det_two_bit_flip_substate   = substates->det_two_bit_flip_strategy->serialize(substates->det_two_bit_flip_substate);
	char *s_det_four_bit_flip_substate  = substates->det_four_bit_flip_strategy->serialize(substates->det_four_bit_flip_substate);
	char *s_det_byte_flip_substate      = substates->det_byte_flip_strategy->serialize(substates->det_byte_flip_substate);
	char *s_det_two_byte_flip_substate  = substates->det_two_byte_flip_strategy->serialize(substates->det_two_byte_flip_substate);
	char *s_det_four_byte_flip_substate = substates->det_four_byte_flip_strategy->serialize(substates->det_four_byte_flip_substate);

	// serialize base strategy structure
	s_state           = strategy_state_serialize(state, "afl_bit_flip");
	size_t total_size = strlen(s_state);

	// serialize current_strategy header
	yaml_serializer *helper;
	size_t           mybuffersize;

	helper = yaml_serializer_init("");
	YAML_SERIALIZE_8HEX_KV(helper, current_substrategy, substates->current_substrategy)
	YAML_SERIALIZE_8HEX_KV(helper, substrategy_complete, substates->substrategy_complete)
	yaml_serializer_end(helper, &s_substrategy_header, &mybuffersize);
	total_size += mybuffersize;

	total_size += strlen(s_det_bit_flip_substate);
	total_size += strlen(s_det_two_bit_flip_substate);
	total_size += strlen(s_det_four_bit_flip_substate);
	total_size += strlen(s_det_byte_flip_substate);
	total_size += strlen(s_det_two_byte_flip_substate);
	total_size += strlen(s_det_four_byte_flip_substate);

	// buffer to hold all serialized data
	char *s_all = calloc(1, total_size + 1);

	// copy serialized state and substates to s_all
	strcat(s_all, s_state);
	strcat(s_all, s_substrategy_header);
	strcat(s_all, s_det_bit_flip_substate);
	strcat(s_all, s_det_two_bit_flip_substate);
	strcat(s_all, s_det_four_bit_flip_substate);
	strcat(s_all, s_det_byte_flip_substate);
	strcat(s_all, s_det_two_byte_flip_substate);
	strcat(s_all, s_det_four_byte_flip_substate);

	// free these, don't need em anymore.
	free(s_state);
	free(s_substrategy_header);
	free(s_det_bit_flip_substate);
	free(s_det_two_bit_flip_substate);
	free(s_det_four_bit_flip_substate);
	free(s_det_byte_flip_substate);
	free(s_det_two_byte_flip_substate);
	free(s_det_four_byte_flip_substate);

	return s_all;
}

// this function deserializes a serialized afl_bit_flip strategy_state object.
static inline strategy_state *
afl_bit_flip_deserialize(char *serialized_state, size_t serialized_state_size)
{
	// pointers to all of the serialized fields and objects
	char *s_substrategy_header;
	char *s_det_bit_flip_substate;
	char *s_det_two_bit_flip_substate;
	char *s_det_four_bit_flip_substate;
	char *s_det_byte_flip_substate;
	char *s_det_two_byte_flip_substate;
	char *s_det_four_byte_flip_substate;

	// create new state object and substates object
	strategy_state         *new_state;
	afl_bit_flip_substates *substates = calloc(1, sizeof(afl_bit_flip_substates));

	// compute start of various state strings
	s_substrategy_header          = strstr(serialized_state, "...") + 4;
	s_det_bit_flip_substate       = strstr(s_substrategy_header, "...") + 4;
	s_det_two_bit_flip_substate   = strstr(s_det_bit_flip_substate, "...") + 4;
	s_det_four_bit_flip_substate  = strstr(s_det_two_bit_flip_substate, "...") + 4;
	s_det_byte_flip_substate      = strstr(s_det_four_bit_flip_substate, "...") + 4;
	s_det_two_byte_flip_substate  = strstr(s_det_byte_flip_substate, "...") + 4;
	s_det_four_byte_flip_substate = strstr(s_det_two_byte_flip_substate, "...") + 4;

	// deserialize base strategy structure;
	new_state = strategy_state_deserialize(serialized_state, serialized_state_size);

	// deserialize substates header
	yaml_deserializer *helper;

	helper = yaml_deserializer_init(NULL, s_substrategy_header, serialized_state_size - (size_t)(s_substrategy_header - serialized_state));

	// Get to the document start
	YAML_DESERIALIZE_PARSE(helper)
	while (helper->event.type != YAML_DOCUMENT_START_EVENT) {
		YAML_DESERIALIZE_EAT(helper)
	}

	YAML_DESERIALIZE_EAT(helper)
	YAML_DESERIALIZE_GET_KV_U8(helper, "current_substrategy", &substates->current_substrategy)
	YAML_DESERIALIZE_GET_KV_U8(helper, "substrategy_complete", &substates->substrategy_complete)

	// Prevent leaking memory
	YAML_DESERIALIZE_EVENT_DELETE(helper)

	yaml_deserializer_end(helper);

	// create empty fuzzing_strategy objects
	substates->det_bit_flip_strategy       = calloc(1, sizeof(fuzzing_strategy));
	substates->det_two_bit_flip_strategy   = calloc(1, sizeof(fuzzing_strategy));
	substates->det_four_bit_flip_strategy  = calloc(1, sizeof(fuzzing_strategy));
	substates->det_byte_flip_strategy      = calloc(1, sizeof(fuzzing_strategy));
	substates->det_two_byte_flip_strategy  = calloc(1, sizeof(fuzzing_strategy));
	substates->det_four_byte_flip_strategy = calloc(1, sizeof(fuzzing_strategy));

	// populate fuzzing_strategy objects
	det_bit_flip_populate(substates->det_bit_flip_strategy);
	det_two_bit_flip_populate(substates->det_two_bit_flip_strategy);
	det_four_bit_flip_populate(substates->det_four_bit_flip_strategy);
	det_byte_flip_populate(substates->det_byte_flip_strategy);
	det_two_byte_flip_populate(substates->det_two_byte_flip_strategy);
	det_four_byte_flip_populate(substates->det_four_byte_flip_strategy);

	// deserialize the substates
	substates->det_bit_flip_substate       = substates->det_bit_flip_strategy->deserialize(s_det_bit_flip_substate, serialized_state_size - (size_t)(s_det_bit_flip_substate - serialized_state));
	substates->det_two_bit_flip_substate   = substates->det_two_bit_flip_strategy->deserialize(s_det_two_bit_flip_substate, serialized_state_size - (size_t)(s_det_two_bit_flip_substate - serialized_state));
	substates->det_four_bit_flip_substate  = substates->det_four_bit_flip_strategy->deserialize(s_det_four_bit_flip_substate, serialized_state_size - (size_t)(s_det_four_bit_flip_substate - serialized_state));
	substates->det_byte_flip_substate      = substates->det_byte_flip_strategy->deserialize(s_det_byte_flip_substate, serialized_state_size - (size_t)(s_det_byte_flip_substate - serialized_state));
	substates->det_two_byte_flip_substate  = substates->det_two_byte_flip_strategy->deserialize(s_det_two_byte_flip_substate, serialized_state_size - (size_t)(s_det_two_byte_flip_substate - serialized_state));
	substates->det_four_byte_flip_substate = substates->det_four_byte_flip_strategy->deserialize(s_det_four_byte_flip_substate, serialized_state_size - (size_t)(s_det_four_byte_flip_substate - serialized_state));

	// update new_state's pointer
	new_state->internal_state = substates;

	return new_state;
}

// this function creates a string that represents afl_bit_flip's state in a human-readable way.
static inline char *
afl_bit_flip_print(strategy_state *state)
{

	afl_bit_flip_substates *substates = (afl_bit_flip_substates *)state->internal_state;

	// serialize all of the strategy states
	char *p_state                       = strategy_state_print(state, "afl_bit_flip");
	char *p_det_bit_flip_substate       = substates->det_bit_flip_strategy->print_state(substates->det_bit_flip_substate);
	char *p_det_two_bit_flip_substate   = substates->det_two_bit_flip_strategy->print_state(substates->det_two_bit_flip_substate);
	char *p_det_four_bit_flip_substate  = substates->det_four_bit_flip_strategy->print_state(substates->det_four_bit_flip_substate);
	char *p_det_byte_flip_substate      = substates->det_byte_flip_strategy->print_state(substates->det_byte_flip_substate);
	char *p_det_two_byte_flip_substate  = substates->det_two_byte_flip_strategy->print_state(substates->det_two_byte_flip_substate);
	char *p_det_four_byte_flip_substate = substates->det_four_byte_flip_strategy->print_state(substates->det_four_byte_flip_substate);

	char buf[64];
	memset(buf, 0, 64);

	size_t total_size = strlen(p_state);

	total_size += strlen(p_det_bit_flip_substate);
	total_size += strlen(p_det_two_bit_flip_substate);
	total_size += strlen(p_det_four_bit_flip_substate);
	total_size += strlen(p_det_byte_flip_substate);
	total_size += strlen(p_det_two_byte_flip_substate);
	total_size += strlen(p_det_four_byte_flip_substate);

	// buffer to hold all serialized data, 128 is probably enough buffer.
	char *p_all = calloc(1, 128 + total_size + 1);

	// copy printed state to buf
	strcat(p_all, p_state);

	// current_substrategy
	sprintf(buf, "Current Substrategy: %02u\n", substates->current_substrategy);
	strcat(p_all, buf);
	memset(buf, 0, 64);

	// substrategy_complete
	sprintf(buf, "Substrategy Complete: %02u\n", substates->substrategy_complete);
	strcat(p_all, buf);

	// copy the printed substates
	strcat(p_all, p_det_bit_flip_substate);
	strcat(p_all, p_det_two_bit_flip_substate);
	strcat(p_all, p_det_four_bit_flip_substate);
	strcat(p_all, p_det_byte_flip_substate);
	strcat(p_all, p_det_two_byte_flip_substate);
	strcat(p_all, p_det_four_byte_flip_substate);

	// free these, don't need em anymore.
	free(p_state);
	free(p_det_bit_flip_substate);
	free(p_det_two_bit_flip_substate);
	free(p_det_four_bit_flip_substate);
	free(p_det_byte_flip_substate);
	free(p_det_two_byte_flip_substate);
	free(p_det_four_byte_flip_substate);

	return p_all;
}

// this function copies an afl_bit_flip strategy_state object.
static inline strategy_state *
afl_bit_flip_copy(strategy_state *state)
{
	afl_bit_flip_substates *substates = (afl_bit_flip_substates *)state->internal_state;

	strategy_state *copy_state = strategy_state_copy(state);

	// craete empty substates object
	afl_bit_flip_substates *substates_copy = calloc(1, sizeof(afl_bit_flip_substates));

	// populate new substates variables
	substates_copy->current_substrategy  = substates->current_substrategy;
	substates_copy->substrategy_complete = substates->substrategy_complete;

	// create empty fuzzing_strategy objects
	substates_copy->det_bit_flip_strategy       = calloc(1, sizeof(fuzzing_strategy));
	substates_copy->det_two_bit_flip_strategy   = calloc(1, sizeof(fuzzing_strategy));
	substates_copy->det_four_bit_flip_strategy  = calloc(1, sizeof(fuzzing_strategy));
	substates_copy->det_byte_flip_strategy      = calloc(1, sizeof(fuzzing_strategy));
	substates_copy->det_two_byte_flip_strategy  = calloc(1, sizeof(fuzzing_strategy));
	substates_copy->det_four_byte_flip_strategy = calloc(1, sizeof(fuzzing_strategy));

	// populate fuzzing_strategy objects
	det_bit_flip_populate(substates_copy->det_bit_flip_strategy);
	det_two_bit_flip_populate(substates_copy->det_two_bit_flip_strategy);
	det_four_bit_flip_populate(substates_copy->det_four_bit_flip_strategy);
	det_byte_flip_populate(substates_copy->det_byte_flip_strategy);
	det_two_byte_flip_populate(substates_copy->det_two_byte_flip_strategy);
	det_four_byte_flip_populate(substates_copy->det_four_byte_flip_strategy);

	// copy the substates
	substates_copy->det_bit_flip_substate       = substates->det_bit_flip_strategy->copy_state(substates->det_bit_flip_substate);
	substates_copy->det_two_bit_flip_substate   = substates->det_two_bit_flip_strategy->copy_state(substates->det_two_bit_flip_substate);
	substates_copy->det_four_bit_flip_substate  = substates->det_four_bit_flip_strategy->copy_state(substates->det_four_bit_flip_substate);
	substates_copy->det_byte_flip_substate      = substates->det_byte_flip_strategy->copy_state(substates->det_byte_flip_substate);
	substates_copy->det_two_byte_flip_substate  = substates->det_two_byte_flip_strategy->copy_state(substates->det_two_byte_flip_substate);
	substates_copy->det_four_byte_flip_substate = substates->det_four_byte_flip_strategy->copy_state(substates->det_four_byte_flip_substate);

	// update internal_state ptr
	copy_state->internal_state = substates_copy;

	return copy_state;
}

// this function frees an afl_bit_flip strategy_state object.
static inline void
afl_bit_flip_free_state(strategy_state *state)
{
    if (do_logging) { 
        fclose(log_file);
    }
	if (state) {
		afl_bit_flip_substates *substates = (afl_bit_flip_substates *)state->internal_state;

		// free substates
		substates->det_bit_flip_strategy->free_state(substates->det_bit_flip_substate);
		substates->det_two_bit_flip_strategy->free_state(substates->det_two_bit_flip_substate);
		substates->det_four_bit_flip_strategy->free_state(substates->det_four_bit_flip_substate);
		substates->det_byte_flip_strategy->free_state(substates->det_byte_flip_substate);
		substates->det_two_byte_flip_strategy->free_state(substates->det_two_byte_flip_substate);
		substates->det_four_byte_flip_strategy->free_state(substates->det_four_byte_flip_substate);

		// free fuzzing_strategies
		free(substates->det_bit_flip_strategy);
		free(substates->det_two_bit_flip_strategy);
		free(substates->det_four_bit_flip_strategy);
		free(substates->det_byte_flip_strategy);
		free(substates->det_two_byte_flip_strategy);
		free(substates->det_four_byte_flip_strategy);

		// free substates container
		free(substates);

		// free state
		free(state);
	}
}

// this function performs the mutation based on the afl_bit_flip strategy_state object.
static inline size_t
afl_bit_flip(u8 *buf, size_t size, strategy_state *state)
{
	afl_bit_flip_substates *substates = (afl_bit_flip_substates *)state->internal_state;
	size_t                  orig_size = size;
        char* stage_name        = NULL;
        bool finished = false;

        do { 
            if (!size && !finished) { 
                afl_bit_flip_update(state); 
            }
            // invoke the correct substrategy
            switch (substates->current_substrategy) {

            case BIT_FLIP:
                stage_name = "bitflip 1/1 "; 
                    size = substates->det_bit_flip_strategy->mutate(buf, size, substates->det_bit_flip_substate);
                    // if substrategy is complete
                    if (!size) {
                            substates->substrategy_complete = 1;
                            //size                            = orig_size; // need to reset bc mutation is not complete
                    }
                    break;

            case TWO_BIT_FLIP:
                stage_name = "bitflip 2/1 "; 
                    size = substates->det_two_bit_flip_strategy->mutate(buf, size, substates->det_two_bit_flip_substate);
                    // if substrategy is complete
                    if (!size) {
                            substates->substrategy_complete = 1;
                            //size                            = orig_size;
                    }
                    break;

            case FOUR_BIT_FLIP:
                stage_name = "bitflip 4/1 "; 
                    size = substates->det_four_bit_flip_strategy->mutate(buf, size, substates->det_four_bit_flip_substate);
                    // if substrategy is complete
                    if (!size) {
                            substates->substrategy_complete = 1;
                            //size                            = orig_size;
                    }
                    break;

            case BYTE_FLIP:
                stage_name = "bitflip 8/8 "; 
                    size = substates->det_byte_flip_strategy->mutate(buf, size, substates->det_byte_flip_substate);
                    // if substrategy is complete
                    if (!size) {
                            substates->substrategy_complete = 1;
                            //size                            = orig_size;
                    }
                    break;

            case TWO_BYTE_FLIP:
                stage_name = "bitflip 16/8 "; 
                    size = substates->det_two_byte_flip_strategy->mutate(buf, size, substates->det_two_byte_flip_substate);
                    // if substrategy is complete
                    if (!size) {
                            substates->substrategy_complete = 1;
                            //size                            = orig_size;
                    }
                    break;

            case FOUR_BYTE_FLIP:
                stage_name = "bitflip 32/8 "; 
                    size = substates->det_four_byte_flip_strategy->mutate(buf, size, substates->det_four_byte_flip_substate);
                    // if substrategy is complete
                    if (!size) {
                            substates->substrategy_complete = 1;
                            finished = true;
                            // size = orig_size;
                    }
                    break;
            // no more substrategies left
            default:
                    // size of 0 signifies mutation is finished.
                    // that is only when FOUR_BYTE_FLIP has completed
                    size = 0;
                    break;
            }
            //printf("size: %lu, finished: %d\n", size, finished); 
        } while (size == 0 && !finished); 

        if (finished) 
            size = 0;
        else 
            size = orig_size;
        // log input here
        if (do_logging && stage_name) { 
            //printf("buf: %s\n", buf); 
            fwrite(stage_name, sizeof(char), strlen(stage_name), log_file); 
            MD5((unsigned char*) buf, size, md5_result);
            write_md5_sum(md5_result, log_file); 
        }


	return size;
}

// this function populates a fuzzing_strategy object with afl_bit_flip's function pointers.
void
afl_bit_flip_populate(fuzzing_strategy *strategy)
{
	strategy->version          = VERSION_ONE;
	strategy->name             = "afl_bit_flip";
	strategy->create_state     = afl_bit_flip_create;
	strategy->mutate           = afl_bit_flip;
	strategy->serialize        = afl_bit_flip_serialize;
	strategy->deserialize      = afl_bit_flip_deserialize;
	strategy->print_state      = afl_bit_flip_print;
	strategy->copy_state       = afl_bit_flip_copy;
	strategy->free_state       = afl_bit_flip_free_state;
	strategy->description      = "This strategy combines all of our bit and byte_flip strategies into one strategy. "
	                             "Note that the single bit flip strategy is excluded. This is because AFL performs instrumentation runs "
	                             "after each single bit flip to detect dictionary tokens.";
	strategy->update_state     = &afl_bit_flip_update;
	strategy->is_deterministic = true;
}
