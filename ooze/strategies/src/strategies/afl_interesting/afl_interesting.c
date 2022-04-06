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

#include "afl_interesting.h"

#include "afl.h"
#include "common/yaml_helper.h"
#include "det_byte_interesting.h"
#include "det_four_byte_interesting_be.h"
#include "det_four_byte_interesting_le.h"
#include "det_two_byte_interesting_be.h"
#include "det_two_byte_interesting_le.h"
#include "strategy.h"
#include "openssl/md5.h"

#ifdef AFL_INTERESTING_IS_MASTER
get_fuzzing_strategy_function get_fuzzing_strategy = afl_interesting_populate;
#endif

#define INTERESTING_8_ELEMENTS INTERESTING_8_SIZE
#define INTERESTING_16_ELEMENTS INTERESTING_8_SIZE + INTERESTING_16_SIZE
#define INTERESTING_32_ELEMENTS INTERESTING_16_ELEMENTS + INTERESTING_32_SIZE

static FILE* log_file; 
static unsigned char md5_result[MD5_DIGEST_LENGTH]; 
static bool do_logging = false;

static void write_md5_sum(unsigned char* md, FILE* fp) { 
    int i;
    for (i = 0; i < MD5_DIGEST_LENGTH;  i++) { 
        fprintf(fp, "%02x", md[i]); 
    }
    fprintf(fp, "\n"); 
}



// this function updates the running states and substates
static inline void
afl_interesting_update(strategy_state *state)
{
	afl_interesting_substates *substates = (afl_interesting_substates *)state->internal_state;

	// if a substrategy was complete, move on to the next substrategy
	if (substates->substrategy_complete) {
		substates->current_substrategy++;
		substates->substrategy_complete = 0;
	} else {
		// update the correct substate
		switch (substates->current_substrategy) {

		case BYTE_INTERESTING:
			substates->det_byte_interesting_strategy->update_state(substates->det_byte_interesting_substate);
			break;

		case TWO_BYTE_INTERESTING_LE:
			substates->det_two_byte_interesting_le_strategy->update_state(substates->det_two_byte_interesting_le_substate);
			break;

		case TWO_BYTE_INTERESTING_BE:
			substates->det_two_byte_interesting_be_strategy->update_state(substates->det_two_byte_interesting_be_substate);
			break;

		case FOUR_BYTE_INTERESTING_LE:
			substates->det_four_byte_interesting_le_strategy->update_state(substates->det_four_byte_interesting_le_substate);
			break;

		case FOUR_BYTE_INTERESTING_BE:
			substates->det_four_byte_interesting_be_strategy->update_state(substates->det_four_byte_interesting_be_substate);
			break;

		default:
			break;
		}
	}
	// update general purpose iterator
	state->iteration++;
}

// creates an afl_interesting strategy_state object.
static inline strategy_state *
afl_interesting_create(u8 *seed, size_t max_size, size_t size, ...)
{

	// create new state and substates objects
	strategy_state            *new_state = strategy_state_create(seed, max_size, size);
	afl_interesting_substates *substates = calloc(1, sizeof(afl_interesting_substates));

	// fill in substates
	substates->current_substrategy  = BYTE_INTERESTING;
	substates->substrategy_complete = 0;

	// create empty fuzzing_strategy objects
	substates->det_byte_interesting_strategy         = calloc(1, sizeof(fuzzing_strategy));
	substates->det_two_byte_interesting_le_strategy  = calloc(1, sizeof(fuzzing_strategy));
	substates->det_two_byte_interesting_be_strategy  = calloc(1, sizeof(fuzzing_strategy));
	substates->det_four_byte_interesting_le_strategy = calloc(1, sizeof(fuzzing_strategy));
	substates->det_four_byte_interesting_be_strategy = calloc(1, sizeof(fuzzing_strategy));

	// populate fuzzing_strategy objects
	det_byte_interesting_populate(substates->det_byte_interesting_strategy);
	det_two_byte_interesting_le_populate(substates->det_two_byte_interesting_le_strategy);
	det_two_byte_interesting_be_populate(substates->det_two_byte_interesting_be_strategy);
	det_four_byte_interesting_le_populate(substates->det_four_byte_interesting_le_strategy);
	det_four_byte_interesting_be_populate(substates->det_four_byte_interesting_be_strategy);

	// create substates
	substates->det_byte_interesting_substate         = substates->det_byte_interesting_strategy->create_state(seed, max_size, size);
	substates->det_two_byte_interesting_le_substate  = substates->det_two_byte_interesting_le_strategy->create_state(seed, max_size, size);
	substates->det_two_byte_interesting_be_substate  = substates->det_two_byte_interesting_be_strategy->create_state(seed, max_size, size);
	substates->det_four_byte_interesting_le_substate = substates->det_four_byte_interesting_le_strategy->create_state(seed, max_size, size);
	substates->det_four_byte_interesting_be_substate = substates->det_four_byte_interesting_be_strategy->create_state(seed, max_size, size);

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
afl_interesting_serialize(strategy_state *state)
{
	afl_interesting_substates *substates = (afl_interesting_substates *)state->internal_state;

	// serialize all of the strategy states
	char *s_state                                 = NULL;
	char *s_substrategy_header                    = NULL;
	char *s_det_byte_interesting_substate         = substates->det_byte_interesting_strategy->serialize(substates->det_byte_interesting_substate);
	char *s_det_two_byte_interesting_le_substate  = substates->det_two_byte_interesting_le_strategy->serialize(substates->det_two_byte_interesting_le_substate);
	char *s_det_two_byte_interesting_be_substate  = substates->det_two_byte_interesting_be_strategy->serialize(substates->det_two_byte_interesting_be_substate);
	char *s_det_four_byte_interesting_le_substate = substates->det_four_byte_interesting_le_strategy->serialize(substates->det_four_byte_interesting_le_substate);
	char *s_det_four_byte_interesting_be_substate = substates->det_four_byte_interesting_be_strategy->serialize(substates->det_four_byte_interesting_be_substate);

	yaml_serializer *helper;
	size_t           mybuffersize;

	// serialized base strategy structure
	s_state = strategy_state_serialize(state, "afl_interesting");

	// serialize current_strategy header
	helper = yaml_serializer_init("");
	YAML_SERIALIZE_8HEX_KV(helper, current_substrategy, substates->current_substrategy)
	YAML_SERIALIZE_8HEX_KV(helper, substrategy_complete, substates->substrategy_complete)
	yaml_serializer_end(helper, &s_substrategy_header, &mybuffersize);

	size_t total_size = strlen(s_state);
	total_size += mybuffersize;
	total_size += strlen(s_det_byte_interesting_substate);
	total_size += strlen(s_det_two_byte_interesting_le_substate);
	total_size += strlen(s_det_two_byte_interesting_be_substate);
	total_size += strlen(s_det_four_byte_interesting_le_substate);
	total_size += strlen(s_det_four_byte_interesting_be_substate);

	// buffer to hold all serialized data
	char *s_all = calloc(1, total_size + 1);

	// copy serialized state and substates to s_all
	strcat(s_all, s_state);
	strcat(s_all, s_substrategy_header);
	strcat(s_all, s_det_byte_interesting_substate);
	strcat(s_all, s_det_two_byte_interesting_le_substate);
	strcat(s_all, s_det_two_byte_interesting_be_substate);
	strcat(s_all, s_det_four_byte_interesting_le_substate);
	strcat(s_all, s_det_four_byte_interesting_be_substate);

	// free these, don't need em anymore.
	free(s_state);
	free(s_substrategy_header);
	free(s_det_byte_interesting_substate);
	free(s_det_two_byte_interesting_le_substate);
	free(s_det_two_byte_interesting_be_substate);
	free(s_det_four_byte_interesting_le_substate);
	free(s_det_four_byte_interesting_be_substate);

	return s_all;
}

// this function deserializes a serialized afl_interesting strategy_state object.
static inline strategy_state *
afl_interesting_deserialize(char *serialized_state, size_t serialized_state_size)
{
	// pointers to all of the serialized fields and objects
	char *s_substrategy_header;
	char *s_det_byte_interesting_substate;
	char *s_det_two_byte_interesting_le_substate;
	char *s_det_two_byte_interesting_be_substate;
	char *s_det_four_byte_interesting_le_substate;
	char *s_det_four_byte_interesting_be_substate;

	// create new state object and substates object
	strategy_state            *new_state;
	afl_interesting_substates *substates = calloc(1, sizeof(afl_interesting_substates));

	// compute start of various state strings
	s_substrategy_header                    = strstr(serialized_state, "...") + 4;
	s_det_byte_interesting_substate         = strstr(s_substrategy_header, "...") + 4;
	s_det_two_byte_interesting_le_substate  = strstr(s_det_byte_interesting_substate, "...") + 4;
	s_det_two_byte_interesting_be_substate  = strstr(s_det_two_byte_interesting_le_substate, "...") + 4;
	s_det_four_byte_interesting_le_substate = strstr(s_det_two_byte_interesting_be_substate, "...") + 4;
	s_det_four_byte_interesting_be_substate = strstr(s_det_four_byte_interesting_le_substate, "...") + 4;

	// deserialize base strategy structure
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
	substates->det_byte_interesting_strategy         = calloc(1, sizeof(fuzzing_strategy));
	substates->det_two_byte_interesting_le_strategy  = calloc(1, sizeof(fuzzing_strategy));
	substates->det_two_byte_interesting_be_strategy  = calloc(1, sizeof(fuzzing_strategy));
	substates->det_four_byte_interesting_le_strategy = calloc(1, sizeof(fuzzing_strategy));
	substates->det_four_byte_interesting_be_strategy = calloc(1, sizeof(fuzzing_strategy));

	// populate fuzzing_strategy objects
	det_byte_interesting_populate(substates->det_byte_interesting_strategy);
	det_two_byte_interesting_le_populate(substates->det_two_byte_interesting_le_strategy);
	det_two_byte_interesting_be_populate(substates->det_two_byte_interesting_be_strategy);
	det_four_byte_interesting_le_populate(substates->det_four_byte_interesting_le_strategy);
	det_four_byte_interesting_be_populate(substates->det_four_byte_interesting_be_strategy);

	// deserialize the substates
	substates->det_byte_interesting_substate         = substates->det_byte_interesting_strategy->deserialize(s_det_byte_interesting_substate, serialized_state_size - (size_t)(s_det_byte_interesting_substate - serialized_state));
	substates->det_two_byte_interesting_le_substate  = substates->det_two_byte_interesting_le_strategy->deserialize(s_det_two_byte_interesting_le_substate, serialized_state_size - (size_t)(s_det_two_byte_interesting_le_substate - serialized_state));
	substates->det_two_byte_interesting_be_substate  = substates->det_two_byte_interesting_be_strategy->deserialize(s_det_two_byte_interesting_be_substate, serialized_state_size - (size_t)(s_det_two_byte_interesting_be_substate - serialized_state));
	substates->det_four_byte_interesting_le_substate = substates->det_four_byte_interesting_le_strategy->deserialize(s_det_four_byte_interesting_le_substate, serialized_state_size - (size_t)(s_det_four_byte_interesting_le_substate - serialized_state));
	substates->det_four_byte_interesting_be_substate = substates->det_four_byte_interesting_be_strategy->deserialize(s_det_four_byte_interesting_be_substate, serialized_state_size - (size_t)(s_det_four_byte_interesting_be_substate - serialized_state));

	// update new_state's pointer
	new_state->internal_state = substates;

	return new_state;
}

// this function creates a string that represents afl_interesting's state in a human-readable way.
static inline char *
afl_interesting_print(strategy_state *state)
{

	afl_interesting_substates *substates = (afl_interesting_substates *)state->internal_state;

	// serialize all of the strategy states
	char *p_state                                 = strategy_state_print(state, "afl_interesting");
	char *p_det_byte_interesting_substate         = substates->det_byte_interesting_strategy->print_state(substates->det_byte_interesting_substate);
	char *p_det_two_byte_interesting_le_substate  = substates->det_two_byte_interesting_le_strategy->print_state(substates->det_two_byte_interesting_le_substate);
	char *p_det_two_byte_interesting_be_substate  = substates->det_two_byte_interesting_be_strategy->print_state(substates->det_two_byte_interesting_be_substate);
	char *p_det_four_byte_interesting_le_substate = substates->det_four_byte_interesting_le_strategy->print_state(substates->det_four_byte_interesting_le_substate);
	char *p_det_four_byte_interesting_be_substate = substates->det_four_byte_interesting_be_strategy->print_state(substates->det_four_byte_interesting_be_substate);

	char buf[64];
	memset(buf, 0, 64);

	size_t total_size = strlen(p_state);

	total_size += strlen(p_det_byte_interesting_substate);
	total_size += strlen(p_det_two_byte_interesting_le_substate);
	total_size += strlen(p_det_two_byte_interesting_be_substate);
	total_size += strlen(p_det_four_byte_interesting_le_substate);
	total_size += strlen(p_det_four_byte_interesting_be_substate);

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
	strcat(p_all, p_det_byte_interesting_substate);
	strcat(p_all, p_det_two_byte_interesting_le_substate);
	strcat(p_all, p_det_two_byte_interesting_be_substate);
	strcat(p_all, p_det_four_byte_interesting_le_substate);
	strcat(p_all, p_det_four_byte_interesting_be_substate);

	// free these, don't need em anymore.
	free(p_state);
	free(p_det_byte_interesting_substate);
	free(p_det_two_byte_interesting_le_substate);
	free(p_det_two_byte_interesting_be_substate);
	free(p_det_four_byte_interesting_le_substate);
	free(p_det_four_byte_interesting_be_substate);

	return p_all;
}

// this function copies an afl_interesting strategy_state object.
static inline strategy_state *
afl_interesting_copy(strategy_state *state)
{
	afl_interesting_substates *substates = (afl_interesting_substates *)state->internal_state;

	strategy_state *copy_state = strategy_state_copy(state);

	// craete empty substates object
	afl_interesting_substates *substates_copy = calloc(1, sizeof(afl_interesting_substates));

	// populate new substates variables
	substates_copy->current_substrategy  = substates->current_substrategy;
	substates_copy->substrategy_complete = substates->substrategy_complete;

	// create empty fuzzing_strategy objects
	substates_copy->det_byte_interesting_strategy         = calloc(1, sizeof(fuzzing_strategy));
	substates_copy->det_two_byte_interesting_le_strategy  = calloc(1, sizeof(fuzzing_strategy));
	substates_copy->det_two_byte_interesting_be_strategy  = calloc(1, sizeof(fuzzing_strategy));
	substates_copy->det_four_byte_interesting_le_strategy = calloc(1, sizeof(fuzzing_strategy));
	substates_copy->det_four_byte_interesting_be_strategy = calloc(1, sizeof(fuzzing_strategy));

	// populate fuzzing_strategy objects
	det_byte_interesting_populate(substates_copy->det_byte_interesting_strategy);
	det_two_byte_interesting_le_populate(substates_copy->det_two_byte_interesting_le_strategy);
	det_two_byte_interesting_be_populate(substates_copy->det_two_byte_interesting_be_strategy);
	det_four_byte_interesting_le_populate(substates_copy->det_four_byte_interesting_le_strategy);
	det_four_byte_interesting_be_populate(substates_copy->det_four_byte_interesting_be_strategy);

	// copy the substates
	substates_copy->det_byte_interesting_substate         = substates->det_byte_interesting_strategy->copy_state(substates->det_byte_interesting_substate);
	substates_copy->det_two_byte_interesting_le_substate  = substates->det_two_byte_interesting_le_strategy->copy_state(substates->det_two_byte_interesting_le_substate);
	substates_copy->det_two_byte_interesting_be_substate  = substates->det_two_byte_interesting_be_strategy->copy_state(substates->det_two_byte_interesting_be_substate);
	substates_copy->det_four_byte_interesting_le_substate = substates->det_four_byte_interesting_le_strategy->copy_state(substates->det_four_byte_interesting_le_substate);
	substates_copy->det_four_byte_interesting_be_substate = substates->det_four_byte_interesting_be_strategy->copy_state(substates->det_four_byte_interesting_be_substate);

	// update internal_state ptr
	copy_state->internal_state = substates_copy;

	return copy_state;
}

// this function frees an afl_interesting strategy_state object.
static inline void
afl_interesting_free_state(strategy_state *state)
{
    if (do_logging) {
        fclose(log_file); 
    }

	if (state) {
		afl_interesting_substates *substates = (afl_interesting_substates *)state->internal_state;

		// free substates
		substates->det_byte_interesting_strategy->free_state(substates->det_byte_interesting_substate);
		substates->det_two_byte_interesting_le_strategy->free_state(substates->det_two_byte_interesting_le_substate);
		substates->det_two_byte_interesting_be_strategy->free_state(substates->det_two_byte_interesting_be_substate);
		substates->det_four_byte_interesting_le_strategy->free_state(substates->det_four_byte_interesting_le_substate);
		substates->det_four_byte_interesting_be_strategy->free_state(substates->det_four_byte_interesting_be_substate);

		// free fuzzing_strategies
		free(substates->det_byte_interesting_strategy);
		free(substates->det_two_byte_interesting_le_strategy);
		free(substates->det_two_byte_interesting_be_strategy);
		free(substates->det_four_byte_interesting_le_strategy);
		free(substates->det_four_byte_interesting_be_strategy);

		// free substates container
		free(substates);

		// free state
		free(state);
	}
}

static inline u64
afl_interesting_get_pos(strategy_state *state)
{
	afl_interesting_substates *substates = (afl_interesting_substates *)state->internal_state;

	u64 pos = 0;
	switch (substates->current_substrategy) {
	case BYTE_INTERESTING:
		pos = substates->det_byte_interesting_substate->iteration / INTERESTING_8_ELEMENTS;
		break;
	case TWO_BYTE_INTERESTING_LE:
		pos = substates->det_two_byte_interesting_le_substate->iteration / ((u64)  INTERESTING_16_ELEMENTS);
		break;
	case TWO_BYTE_INTERESTING_BE:
		pos = substates->det_two_byte_interesting_be_substate->iteration / ((u64)  INTERESTING_16_ELEMENTS);
		break;
	case FOUR_BYTE_INTERESTING_LE:
                //printf("sub iter: %lu, state iter: %lu\n", state->iteration, substates->det_four_byte_interesting_le_substate->iteration
		pos = substates->det_four_byte_interesting_le_substate->iteration / 27; //((u64)  INTERESTING_32_ELEMENTS);
		break;
	case FOUR_BYTE_INTERESTING_BE:
		pos = substates->det_four_byte_interesting_be_substate->iteration /  27; //((u64)  INTERESTING_32_ELEMENTS);
		break;
	}
	return pos;
}

static inline u8 
afl_interesting_get_j(strategy_state *state) 
{ 
	afl_interesting_substates *substates = (afl_interesting_substates *)state->internal_state;
	u8  which = 0;

	switch (substates->current_substrategy) {
	case BYTE_INTERESTING:
		which = substates->det_byte_interesting_substate->iteration % INTERESTING_8_SIZE;
		break;
	case TWO_BYTE_INTERESTING_LE:
		which = substates->det_two_byte_interesting_le_substate->iteration % (INTERESTING_8_SIZE + INTERESTING_16_SIZE);
		break;
	case TWO_BYTE_INTERESTING_BE:
		which = substates->det_two_byte_interesting_be_substate->iteration % (INTERESTING_8_SIZE + INTERESTING_16_SIZE);
		break;
	case FOUR_BYTE_INTERESTING_LE:
		which = substates->det_four_byte_interesting_le_substate->iteration % 27; //((u64) INTERESTING_32_ELEMENTS); //(INTERESTING_8_SIZE + INTERESTING_16_SIZE + INTERESTING_32_SIZE);
		break;
	case FOUR_BYTE_INTERESTING_BE:
		which = substates->det_four_byte_interesting_be_substate->iteration % 27; //((u64) INTERESTING_32_ELEMENTS); //(INTERESTING_8_SIZE + INTERESTING_16_SIZE + INTERESTING_32_SIZE);

		break;
	}
	return which; 
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-statement-expression"
static inline s32
afl_interesting_get_value(strategy_state *state)
{
	afl_interesting_substates *substates = (afl_interesting_substates *)state->internal_state;

	s32 value = 0;
	u8  j = afl_interesting_get_j(state);

	switch (substates->current_substrategy) {
	case BYTE_INTERESTING:
		value = (s8)interesting_8[j]; 
		break;
	case TWO_BYTE_INTERESTING_LE:
		value = (s16)interesting_16[j]; 
		break;
	case TWO_BYTE_INTERESTING_BE:
		value = (s16)((u16)interesting_16[j]); 
		break;
	case FOUR_BYTE_INTERESTING_LE:
		value = (s32)interesting_32[j]; 
		break;
	case FOUR_BYTE_INTERESTING_BE:
		value = (s32)interesting_32[j];
		break;
	}
	return value;
}
#pragma clang diagnostic pop

static inline bool
afl_interesting_check_pos(u64 pos, u8 j, strategy_state *state)
{
	afl_interesting_substates *substates = (afl_interesting_substates *)state->internal_state;

	switch (substates->current_substrategy) {
	case BYTE_INTERESTING:
		return pos >= state->max_size || j >= ((u64) INTERESTING_8_ELEMENTS);
	case TWO_BYTE_INTERESTING_LE:
		return pos + 2 > state->max_size || j >= (((u64) INTERESTING_16_ELEMENTS));
	case TWO_BYTE_INTERESTING_BE:
		return pos + 2 > state->max_size || j >= (((u64) INTERESTING_16_ELEMENTS));
	case FOUR_BYTE_INTERESTING_LE:
		return pos + 4 > state->max_size || j >= (((u64) INTERESTING_32_ELEMENTS));
	case FOUR_BYTE_INTERESTING_BE:
		return pos + 4 > state->max_size || j >= (((u64) INTERESTING_32_ELEMENTS));
	default:
		return 0;
	}
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-statement-expression"
static inline bool
afl_interesting_check_could_be_list(u8 *buf, strategy_state *state)
{
	afl_interesting_substates *substates = (afl_interesting_substates *)state->internal_state;

	u64 pos      = afl_interesting_get_pos(state);
	s32 value    = afl_interesting_get_value(state);
	u8  orig_u8  = 0;
	u16 orig_u16 = 0;
	u32 orig_u32 = 0;
	switch (substates->current_substrategy) {

	case BYTE_INTERESTING:
		orig_u8 = buf[pos];
		return (
		    !could_be_bitflip(orig_u8 ^ (u8)value) &&
		    !could_be_arith(orig_u8, (u32)value, 1));
	case TWO_BYTE_INTERESTING_LE:
		orig_u16 = *(u16 *)((u64)buf + pos);
		return (
		    !could_be_bitflip(orig_u16 ^ (u16)value) &&
		    !could_be_arith(orig_u16, (u16)value, 2) &&
		    !could_be_interest(orig_u16, (u16)value, 2, 0));
	case TWO_BYTE_INTERESTING_BE:
		orig_u16 = *(u16 *)((u64)buf + pos);
		return (
		    (u16)value != SWAP16((u16)value) &&
		    !could_be_bitflip(orig_u16 ^ SWAP16((u16)value)) &&
		    !could_be_arith(orig_u16, SWAP16((u16)value), 2) &&
		    !could_be_interest(orig_u16, SWAP16((u16)value), 2, 1));
	case FOUR_BYTE_INTERESTING_LE:
		orig_u32 = *(u32 *)((u64)buf + pos);
		return (
		    !could_be_bitflip(orig_u32 ^ (u32)value) &&
		    !could_be_arith(orig_u32, (u32)value, 4) &&
		    !could_be_interest(orig_u32, (u32)value, 4, 0));
	case FOUR_BYTE_INTERESTING_BE:
		orig_u32 = *(u32 *)((u64)buf + pos);
		return (
		    (u32)value != SWAP32((u32)value) &&
		    !could_be_bitflip(orig_u32 ^ SWAP32((u32)value)) &&
		    !could_be_arith(orig_u32, SWAP32((u32)value), 4) &&
		    !could_be_interest(orig_u32, SWAP32((u32)value), 4, 1));
	default:
		return false;
	}
}
#pragma clang diagnostic pop


static inline size_t
afl_interesting(u8 *buf, size_t size, strategy_state *state)
{
	afl_interesting_substates *substates = (afl_interesting_substates *)state->internal_state;
	size_t                     orig_size = size;
	u64                        pos;
        u8                         j; 
        char*                      stage_name = NULL;
        char*                      endian = NULL;

	while (size) {

		pos = afl_interesting_get_pos(state);  // this is i
            	j = afl_interesting_get_j(state); // this is j
            	//printf("strategy: %d, i: %lu, j: %u, \n", substates->current_substrategy, pos, j); 

		// if the position would lead to an out of bounds mutation,
		// skip to the next mutation substrategy.
		if (afl_interesting_check_pos(pos, j, state)) {
			substates->substrategy_complete = 1;

                    	// If it's the last strategy we need to return size of 0
                    	if (substates->current_substrategy == FOUR_BYTE_INTERESTING_BE) { 
                        	size = 0;
                        	return size;
                    	}

                    	// If not, we can update and move on to next 
			afl_interesting_update(state);
		}
		// If the input we are about to generate was not produced by a previous mutation strategy.
		else if (afl_interesting_check_could_be_list(buf, state)) {

			// invoke the correct substrategy
			switch (substates->current_substrategy) {

			case BYTE_INTERESTING:
                            stage_name = "interest 8/8 "; 
				size = substates->det_byte_interesting_strategy->mutate(buf, size, substates->det_byte_interesting_substate);
				// if substrategy is complete
				if (!size) {
					substates->substrategy_complete = 1;
					size                            = orig_size;
				}
				break;

			case TWO_BYTE_INTERESTING_LE:
                            stage_name = "interest 16/8 "; 
                            endian = "LE "; 
				size = substates->det_two_byte_interesting_le_strategy->mutate(buf, size, substates->det_two_byte_interesting_le_substate);
				// if substrategy is complete
				if (!size) {
					substates->substrategy_complete = 1;
					size                            = orig_size;
				}
				break;

			case TWO_BYTE_INTERESTING_BE:
                            stage_name = "interest 16/8 "; 
                            endian = "BE "; 
				size = substates->det_two_byte_interesting_be_strategy->mutate(buf, size, substates->det_two_byte_interesting_be_substate);
				// if substrategy is complete
				if (!size) {
					substates->substrategy_complete = 1;
					size                            = orig_size;
				}
				break;

			case FOUR_BYTE_INTERESTING_LE:
                            stage_name = "interest 32/8 "; 
                            endian = "LE "; 
				size = substates->det_four_byte_interesting_le_strategy->mutate(buf, size, substates->det_four_byte_interesting_le_substate);
				// if substrategy is complete
				if (!size) {
                                    printf("done le\n");
					substates->substrategy_complete = 1;
					size                            = orig_size;
				}
				break;

			case FOUR_BYTE_INTERESTING_BE:
                            stage_name = "interest 32/8 "; 
                            endian = "BE "; 
				size = substates->det_four_byte_interesting_be_strategy->mutate(buf, size, substates->det_four_byte_interesting_be_substate);
				// if substrategy is complete
				if (!size)
					substates->substrategy_complete = 1;

				break;
			// no more substrategies left
			default:
				// size of 0 signifies mutation is finished.
				size = 0;
				break;
			}
			// We're done, we can break out of the while loop.
			break;
		}
		// Duplicate mutation, skip it and go to the next one.
		else {
			afl_interesting_update(state);
		}
	}
        if (do_logging && stage_name) {
            if (endian) { 
                fwrite(endian, sizeof(char), strlen(endian), log_file);
            }
            fwrite(stage_name, sizeof(char), strlen(stage_name), log_file); 
            MD5((unsigned char*) buf, size, md5_result);
            write_md5_sum(md5_result, log_file); 
        }

	return size;
}

// this function populates a fuzzing_strategy object with afl_interesting's function pointers.
void
afl_interesting_populate(fuzzing_strategy *strategy)
{
	strategy->version          = VERSION_ONE;
	strategy->name             = "afl_interesting";
	strategy->create_state     = afl_interesting_create;
	strategy->mutate           = afl_interesting;
	strategy->serialize        = afl_interesting_serialize;
	strategy->deserialize      = afl_interesting_deserialize;
	strategy->print_state      = afl_interesting_print;
	strategy->copy_state       = afl_interesting_copy;
	strategy->free_state       = afl_interesting_free_state;
	strategy->description      = "This strategy combines all of our 'interesting' strategies into one strategy.";
	strategy->update_state     = &afl_interesting_update;
	strategy->is_deterministic = true;
}
