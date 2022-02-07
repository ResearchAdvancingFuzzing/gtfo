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

#include "afl.h"
#include "afl_arith.h"
#include "common/yaml_helper.h"
#include "det_byte_arith.h"
#include "det_four_byte_arith_be.h"
#include "det_four_byte_arith_le.h"
#include "det_two_byte_arith_be.h"
#include "det_two_byte_arith_le.h"
#include "strategy.h"

#ifdef AFL_ARITH_IS_MASTER
get_fuzzing_strategy_function get_fuzzing_strategy = afl_arith_populate;
#endif

// this function updates the running states and substates
static inline void
afl_arith_update(strategy_state *state)
{
	afl_arith_substates *substates = (afl_arith_substates *)state->internal_state;

	// if a substrategy was complete, move on to the next substrategy
	if (substates->substrategy_complete) {
		substates->current_substrategy++;
		substates->substrategy_complete = 0;
	} else {
		// update the correct substate
		switch (substates->current_substrategy) {

		case BYTE_ARITH:
			substates->det_byte_arith_strategy->update_state(substates->det_byte_arith_substate);
			break;

		case TWO_BYTE_ARITH_LE:
			substates->det_two_byte_arith_le_strategy->update_state(substates->det_two_byte_arith_le_substate);
			break;

		case TWO_BYTE_ARITH_BE:
			substates->det_two_byte_arith_be_strategy->update_state(substates->det_two_byte_arith_be_substate);
			break;

		case FOUR_BYTE_ARITH_LE:
			substates->det_four_byte_arith_le_strategy->update_state(substates->det_four_byte_arith_le_substate);
			break;

		case FOUR_BYTE_ARITH_BE:
			substates->det_four_byte_arith_be_strategy->update_state(substates->det_four_byte_arith_be_substate);
			break;

		default:
			break;
		}
	}
	// update general purpose iterator
	state->iteration++;
}

// create a new afl_arith strategy_state object.
static inline strategy_state *
afl_arith_create(u8 *seed, size_t max_size, ...)
{

	// create new state and substates objects
	strategy_state      *new_state = strategy_state_create(seed, max_size);
	afl_arith_substates *substates = calloc(1, sizeof(afl_arith_substates));

	// fill in substates
	substates->current_substrategy  = BYTE_ARITH;
	substates->substrategy_complete = 0;

	// create empty fuzzing_strategy objects
	substates->det_byte_arith_strategy         = calloc(1, sizeof(fuzzing_strategy));
	substates->det_two_byte_arith_le_strategy  = calloc(1, sizeof(fuzzing_strategy));
	substates->det_two_byte_arith_be_strategy  = calloc(1, sizeof(fuzzing_strategy));
	substates->det_four_byte_arith_le_strategy = calloc(1, sizeof(fuzzing_strategy));
	substates->det_four_byte_arith_be_strategy = calloc(1, sizeof(fuzzing_strategy));

	// populate fuzzing_strategy objects
	det_byte_arith_populate(substates->det_byte_arith_strategy);
	det_two_byte_arith_le_populate(substates->det_two_byte_arith_le_strategy);
	det_two_byte_arith_be_populate(substates->det_two_byte_arith_be_strategy);
	det_four_byte_arith_le_populate(substates->det_four_byte_arith_le_strategy);
	det_four_byte_arith_be_populate(substates->det_four_byte_arith_be_strategy);

	// create substates
	substates->det_byte_arith_substate         = substates->det_byte_arith_strategy->create_state(seed, max_size);
	substates->det_two_byte_arith_le_substate  = substates->det_two_byte_arith_le_strategy->create_state(seed, max_size);
	substates->det_two_byte_arith_be_substate  = substates->det_two_byte_arith_be_strategy->create_state(seed, max_size);
	substates->det_four_byte_arith_le_substate = substates->det_four_byte_arith_le_strategy->create_state(seed, max_size);
	substates->det_four_byte_arith_be_substate = substates->det_four_byte_arith_be_strategy->create_state(seed, max_size);

	new_state->internal_state = substates;

	return new_state;
}

// this function serializes an afl_arith strategy state object.
static inline char *
afl_arith_serialize(strategy_state *state)
{
	afl_arith_substates *substates = (afl_arith_substates *)state->internal_state;

	// serialize all of the strategy states
	char *s_state                           = NULL;
	char *s_substrategy_header              = NULL;
	char *s_det_byte_arith_substate         = substates->det_byte_arith_strategy->serialize(substates->det_byte_arith_substate);
	char *s_det_two_byte_arith_le_substate  = substates->det_two_byte_arith_le_strategy->serialize(substates->det_two_byte_arith_le_substate);
	char *s_det_two_byte_arith_be_substate  = substates->det_two_byte_arith_be_strategy->serialize(substates->det_two_byte_arith_be_substate);
	char *s_det_four_byte_arith_le_substate = substates->det_four_byte_arith_le_strategy->serialize(substates->det_four_byte_arith_le_substate);
	char *s_det_four_byte_arith_be_substate = substates->det_four_byte_arith_be_strategy->serialize(substates->det_four_byte_arith_be_substate);

	yaml_serializer *helper;
	size_t           mybuffersize;

	// serialize base strategy structure
	s_state = strategy_state_serialize(state, "afl_arith");

	// serialize current_strategy header
	helper = yaml_serializer_init("");
	YAML_SERIALIZE_8HEX_KV(helper, current_substrategy, substates->current_substrategy)
	YAML_SERIALIZE_8HEX_KV(helper, substrategy_complete, substates->substrategy_complete)
	yaml_serializer_end(helper, &s_substrategy_header, &mybuffersize);

	size_t total_size = strlen(s_state);
	total_size += mybuffersize;
	total_size += strlen(s_det_byte_arith_substate);
	total_size += strlen(s_det_two_byte_arith_le_substate);
	total_size += strlen(s_det_two_byte_arith_be_substate);
	total_size += strlen(s_det_four_byte_arith_le_substate);
	total_size += strlen(s_det_four_byte_arith_be_substate);

	// buffer to hold all serialized data
	char *s_all = calloc(1, total_size + 1);

	// copy serialized state and substates to s_all
	strcat(s_all, s_state);
	strcat(s_all, s_substrategy_header);
	strcat(s_all, s_det_byte_arith_substate);
	strcat(s_all, s_det_two_byte_arith_le_substate);
	strcat(s_all, s_det_two_byte_arith_be_substate);
	strcat(s_all, s_det_four_byte_arith_le_substate);
	strcat(s_all, s_det_four_byte_arith_be_substate);

	// free these, don't need em anymore.
	free(s_state);
	free(s_substrategy_header);
	free(s_det_byte_arith_substate);
	free(s_det_two_byte_arith_le_substate);
	free(s_det_two_byte_arith_be_substate);
	free(s_det_four_byte_arith_le_substate);
	free(s_det_four_byte_arith_be_substate);

	return s_all;
}

// this function deserializes a serialized afl_arith strategy_state object.
static inline strategy_state *
afl_arith_deserialize(char *serialized_state, size_t serialized_state_size)
{
	// pointers to all of the serialized fields and objects
	char *s_substrategy_header;
	char *s_det_byte_arith_substate;
	char *s_det_two_byte_arith_le_substate;
	char *s_det_two_byte_arith_be_substate;
	char *s_det_four_byte_arith_le_substate;
	char *s_det_four_byte_arith_be_substate;

	// create new state object and substates object
	strategy_state      *new_state;
	afl_arith_substates *substates = calloc(1, sizeof(afl_arith_substates));

	new_state = strategy_state_deserialize(serialized_state, serialized_state_size);

	// compute start of various state strings
	s_substrategy_header              = strstr(serialized_state, "...") + 4;
	s_det_byte_arith_substate         = strstr(s_substrategy_header, "...") + 4;
	s_det_two_byte_arith_le_substate  = strstr(s_det_byte_arith_substate, "...") + 4;
	s_det_two_byte_arith_be_substate  = strstr(s_det_two_byte_arith_le_substate, "...") + 4;
	s_det_four_byte_arith_le_substate = strstr(s_det_two_byte_arith_be_substate, "...") + 4;
	s_det_four_byte_arith_be_substate = strstr(s_det_four_byte_arith_le_substate, "...") + 4;

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
	substates->det_byte_arith_strategy         = calloc(1, sizeof(fuzzing_strategy));
	substates->det_two_byte_arith_le_strategy  = calloc(1, sizeof(fuzzing_strategy));
	substates->det_two_byte_arith_be_strategy  = calloc(1, sizeof(fuzzing_strategy));
	substates->det_four_byte_arith_le_strategy = calloc(1, sizeof(fuzzing_strategy));
	substates->det_four_byte_arith_be_strategy = calloc(1, sizeof(fuzzing_strategy));

	// populate fuzzing_strategy objects
	det_byte_arith_populate(substates->det_byte_arith_strategy);
	det_two_byte_arith_le_populate(substates->det_two_byte_arith_le_strategy);
	det_two_byte_arith_be_populate(substates->det_two_byte_arith_be_strategy);
	det_four_byte_arith_le_populate(substates->det_four_byte_arith_le_strategy);
	det_four_byte_arith_be_populate(substates->det_four_byte_arith_be_strategy);

	// deserialize the substates
	substates->det_byte_arith_substate         = substates->det_byte_arith_strategy->deserialize(s_det_byte_arith_substate, serialized_state_size - (size_t)(s_det_byte_arith_substate - serialized_state));
	substates->det_two_byte_arith_le_substate  = substates->det_two_byte_arith_le_strategy->deserialize(s_det_two_byte_arith_le_substate, serialized_state_size - (size_t)(s_det_two_byte_arith_le_substate - serialized_state));
	substates->det_two_byte_arith_be_substate  = substates->det_two_byte_arith_be_strategy->deserialize(s_det_two_byte_arith_be_substate, serialized_state_size - (size_t)(s_det_two_byte_arith_be_substate - serialized_state));
	substates->det_four_byte_arith_le_substate = substates->det_four_byte_arith_le_strategy->deserialize(s_det_four_byte_arith_le_substate, serialized_state_size - (size_t)(s_det_four_byte_arith_le_substate - serialized_state));
	substates->det_four_byte_arith_be_substate = substates->det_four_byte_arith_be_strategy->deserialize(s_det_four_byte_arith_be_substate, serialized_state_size - (size_t)(s_det_four_byte_arith_be_substate - serialized_state));

	// update new_state's pointer
	new_state->internal_state = substates;

	return new_state;
}

// this function creates a string that represents afl_arith's state in a human-readable way.
static inline char *
afl_arith_print(strategy_state *state)
{

	afl_arith_substates *substates = (afl_arith_substates *)state->internal_state;

	// serialize all of the strategy states
	char *p_state                           = strategy_state_print(state, "afl_arith");
	char *p_det_byte_arith_substate         = substates->det_byte_arith_strategy->print_state(substates->det_byte_arith_substate);
	char *p_det_two_byte_arith_le_substate  = substates->det_two_byte_arith_le_strategy->print_state(substates->det_two_byte_arith_le_substate);
	char *p_det_two_byte_arith_be_substate  = substates->det_two_byte_arith_be_strategy->print_state(substates->det_two_byte_arith_be_substate);
	char *p_det_four_byte_arith_le_substate = substates->det_four_byte_arith_le_strategy->print_state(substates->det_four_byte_arith_le_substate);
	char *p_det_four_byte_arith_be_substate = substates->det_four_byte_arith_be_strategy->print_state(substates->det_four_byte_arith_be_substate);

	char buf[64];
	memset(buf, 0, 64);

	size_t total_size = strlen(p_state);

	total_size += strlen(p_det_byte_arith_substate);
	total_size += strlen(p_det_two_byte_arith_le_substate);
	total_size += strlen(p_det_two_byte_arith_be_substate);
	total_size += strlen(p_det_four_byte_arith_le_substate);
	total_size += strlen(p_det_four_byte_arith_be_substate);

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
	strcat(p_all, p_det_byte_arith_substate);
	strcat(p_all, p_det_two_byte_arith_le_substate);
	strcat(p_all, p_det_two_byte_arith_be_substate);
	strcat(p_all, p_det_four_byte_arith_le_substate);
	strcat(p_all, p_det_four_byte_arith_be_substate);

	// free these, don't need em anymore.
	free(p_state);
	free(p_det_byte_arith_substate);
	free(p_det_two_byte_arith_le_substate);
	free(p_det_two_byte_arith_be_substate);
	free(p_det_four_byte_arith_le_substate);
	free(p_det_four_byte_arith_be_substate);

	return p_all;
}

// this function copies an afl_arith strategy_state object.
static inline strategy_state *
afl_arith_copy(strategy_state *state)
{
	afl_arith_substates *substates = (afl_arith_substates *)state->internal_state;

	strategy_state *copy_state = strategy_state_copy(state);

	// craete empty substates object
	afl_arith_substates *substates_copy = calloc(1, sizeof(afl_arith_substates));

	// populate new substates variables
	substates_copy->current_substrategy  = substates->current_substrategy;
	substates_copy->substrategy_complete = substates->substrategy_complete;

	// create empty fuzzing_strategy objects
	substates_copy->det_byte_arith_strategy         = calloc(1, sizeof(fuzzing_strategy));
	substates_copy->det_two_byte_arith_le_strategy  = calloc(1, sizeof(fuzzing_strategy));
	substates_copy->det_two_byte_arith_be_strategy  = calloc(1, sizeof(fuzzing_strategy));
	substates_copy->det_four_byte_arith_le_strategy = calloc(1, sizeof(fuzzing_strategy));
	substates_copy->det_four_byte_arith_be_strategy = calloc(1, sizeof(fuzzing_strategy));

	// populate fuzzing_strategy objects
	det_byte_arith_populate(substates_copy->det_byte_arith_strategy);
	det_two_byte_arith_le_populate(substates_copy->det_two_byte_arith_le_strategy);
	det_two_byte_arith_be_populate(substates_copy->det_two_byte_arith_be_strategy);
	det_four_byte_arith_le_populate(substates_copy->det_four_byte_arith_le_strategy);
	det_four_byte_arith_be_populate(substates_copy->det_four_byte_arith_be_strategy);

	// copy the substates
	substates_copy->det_byte_arith_substate         = substates->det_byte_arith_strategy->copy_state(substates->det_byte_arith_substate);
	substates_copy->det_two_byte_arith_le_substate  = substates->det_two_byte_arith_le_strategy->copy_state(substates->det_two_byte_arith_le_substate);
	substates_copy->det_two_byte_arith_be_substate  = substates->det_two_byte_arith_be_strategy->copy_state(substates->det_two_byte_arith_be_substate);
	substates_copy->det_four_byte_arith_le_substate = substates->det_four_byte_arith_le_strategy->copy_state(substates->det_four_byte_arith_le_substate);
	substates_copy->det_four_byte_arith_be_substate = substates->det_four_byte_arith_be_strategy->copy_state(substates->det_four_byte_arith_be_substate);

	// update internal_state ptr
	copy_state->internal_state = substates_copy;

	return copy_state;
}

// this function frees an afl_arith strategy_state object.
static inline void
afl_arith_free_state(strategy_state *state)
{
	if (state) {
		afl_arith_substates *substates = (afl_arith_substates *)state->internal_state;

		// free substates
		substates->det_byte_arith_strategy->free_state(substates->det_byte_arith_substate);
		substates->det_two_byte_arith_le_strategy->free_state(substates->det_two_byte_arith_le_substate);
		substates->det_two_byte_arith_be_strategy->free_state(substates->det_two_byte_arith_be_substate);
		substates->det_four_byte_arith_le_strategy->free_state(substates->det_four_byte_arith_le_substate);
		substates->det_four_byte_arith_be_strategy->free_state(substates->det_four_byte_arith_be_substate);

		// free fuzzing_strategies
		free(substates->det_byte_arith_strategy);
		free(substates->det_two_byte_arith_le_strategy);
		free(substates->det_two_byte_arith_be_strategy);
		free(substates->det_four_byte_arith_le_strategy);
		free(substates->det_four_byte_arith_be_strategy);

		// free substates container
		free(substates);

		// free state
		free(state);
	}
}

static inline u64
afl_arith_get_pos(strategy_state *state)
{
	afl_arith_substates *substates = (afl_arith_substates *)state->internal_state;

	u64 pos = 0;
	switch (substates->current_substrategy) {
	case BYTE_ARITH:
		//("afl_arith_get_pos: det_byte_arith iteration = %lu\n", substates->det_byte_arith_substate->iteration);
		pos = substates->det_byte_arith_substate->iteration / (MAX_ARITH * 2);
		break;
	case TWO_BYTE_ARITH_LE:
		//("afl_arith_get_pos: det_two_byte_arith_le iteration = %lu\n", substates->det_two_byte_arith_le_substate->iteration);

		pos = substates->det_two_byte_arith_le_substate->iteration / (MAX_ARITH * 2);
		break;
	case TWO_BYTE_ARITH_BE:
		//("afl_arith_get_pos: det_two_byte_arith_be iteration = %lu\n", substates->det_two_byte_arith_be_substate->iteration);

		pos = substates->det_two_byte_arith_be_substate->iteration / (MAX_ARITH * 2);
		break;
	case FOUR_BYTE_ARITH_LE:
		//("afl_arith_get_pos: det_four_byte_arith_le iteration = %lu\n", substates->det_four_byte_arith_le_substate->iteration);

		pos = substates->det_four_byte_arith_le_substate->iteration / (MAX_ARITH * 2);
		break;
	case FOUR_BYTE_ARITH_BE:
		//("afl_arith_get_pos: det_four_byte_arith_be iteration = %lu\n", substates->det_four_byte_arith_be_substate->iteration);
		pos = substates->det_four_byte_arith_be_substate->iteration / (MAX_ARITH * 2);
		break;
	}
	//("afl_arith_get_pos: pos = %lu\n", pos);
	return pos;
}

static inline void
afl_arith_copy_bytes(u32 *src, u32 *dest, strategy_state *state)
{
	afl_arith_substates *substates = (afl_arith_substates *)state->internal_state;

	switch (substates->current_substrategy) {
	case BYTE_ARITH:
		memcpy(dest, src, 1);
		break;
	case TWO_BYTE_ARITH_LE:
		memcpy(dest, src, 2);
		break;
	case TWO_BYTE_ARITH_BE:
		memcpy(dest, src, 2);
		break;
	case FOUR_BYTE_ARITH_LE:
		memcpy(dest, src, 4);
		break;
	case FOUR_BYTE_ARITH_BE:
		memcpy(dest, src, 4);
		break;
	}
}

static inline bool
afl_arith_check_pos(u64 pos, strategy_state *state)
{
	afl_arith_substates *substates = (afl_arith_substates *)state->internal_state;

	switch (substates->current_substrategy) {
	case BYTE_ARITH:
		return pos >= state->max_size;
	case TWO_BYTE_ARITH_LE:
		return pos + 2 > state->max_size;
	case TWO_BYTE_ARITH_BE:
		return pos + 2 > state->max_size;
	case FOUR_BYTE_ARITH_LE:
		return pos + 4 > state->max_size;
	case FOUR_BYTE_ARITH_BE:
		return pos + 4 > state->max_size;
	default:
		return 0;
	}
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-statement-expression"
static inline bool
afl_arith_should_skip_mutation(strategy_state *state, u32 orig_bytes)
{
	afl_arith_substates *substates = (afl_arith_substates *)state->internal_state;
	u8                   which;
	u16                  abs_val;
	u16                  orig_bytes_u16;

	switch (substates->current_substrategy) {

	case BYTE_ARITH:
		return false;

	case TWO_BYTE_ARITH_LE:
		// first two bytes of the original bytes to be mutated
		orig_bytes_u16 = (u16)(orig_bytes >> 16);
		which          = (substates->det_two_byte_arith_le_substate->iteration % (MAX_ARITH * 2));
		abs_val        = (u16)(which / 2) + 1;

		// if we're doing addition,and addition would cause an overflow of the first byte, we should not skip
		if (!(which % 2) && (orig_bytes_u16 & 0xFF) + abs_val > 0xFF)
			return false;
		// if we're doing subtraction, and subtraction would cause an underflow of the first byte, we should not skip.
		if ((which % 2) && (orig_bytes_u16 & 0xFF) < abs_val)
			return false;

		break;
	case TWO_BYTE_ARITH_BE:
		// first two bytes of the original bytes to be mutated
		orig_bytes_u16 = (u16)(orig_bytes >> 16);
		which          = (substates->det_two_byte_arith_be_substate->iteration % (MAX_ARITH * 2));
		abs_val        = (u16)(which / 2) + 1;

		// if we're doing addition,and addition would cause an overflow of the first byte, we should not skip
		if (!(which % 2) && ((orig_bytes_u16 >> 8) + abs_val) > 0xFF)
			return false;
		// if we're doing subtraction, and subtraction would cause an underflow of the first byte, we should not skip.
		if ((which % 2) && ((orig_bytes_u16 >> 8) < abs_val))
			return false;

		break;

	case FOUR_BYTE_ARITH_LE:
		which   = (substates->det_four_byte_arith_le_substate->iteration % (MAX_ARITH * 2));
		abs_val = (u16)(which / 2) + 1;

		// if we're doing addition,and addition would cause an overflow of the first two bytes, we should not skip
		if (!(which % 2) && ((orig_bytes & 0xFFFF) + abs_val) > 0xFFFF)
			return false;
		// if we're doing subtraction, and subtraction would cause an underflow of the first two bytes, we should not skip.
		if ((which % 2) && (orig_bytes & 0xFFFF) < abs_val)
			return false;

		break;

	case FOUR_BYTE_ARITH_BE:
		which   = (substates->det_four_byte_arith_be_substate->iteration % (MAX_ARITH * 2));
		abs_val = (u16)(which / 2) + 1;

		// if we're doing addition,and addition would cause an overflow of the first two bytes, we should not skip
		if (!(which % 2) && ((SWAP32(orig_bytes) & 0xFFFF) + abs_val) > 0xFFFF)
			return false;
		// if we're doing subtraction, and subtraction would cause an underflow of the first two bytes, we should not skip.
		if ((which % 2) && (SWAP32(orig_bytes) & 0xFFFF) < abs_val)
			return false;

		break;
	}
	return true;
}
#pragma clang diagnostic pop

static inline size_t
afl_arith(u8 *buf, size_t size, strategy_state *state)
{
	afl_arith_substates *substates  = (afl_arith_substates *)state->internal_state;
	size_t               orig_size  = size;
	u32                  orig_bytes = 0;
	// get initial position
	u64  pos         = 0;
	bool pos_changed = true;

	while (size) {
		u64 new_pos = afl_arith_get_pos(state);
		// check for position change, if position changed, we need to update orig_bytes later.
		if (pos != new_pos) {
			pos         = new_pos;
			pos_changed = true;
		}
		// if the position would lead to an out of bounds mutation,
		// skip to the next mutation.
		if (afl_arith_check_pos(pos, state)) {
			substates->substrategy_complete = 1;
			afl_arith_update(state);
			continue;
		}
		// if the position we are mutating is valid and has changed, we need to make a new backup
		// of the bytes at that position.
		if (pos_changed) {
			afl_arith_copy_bytes((void *)&buf[pos], &orig_bytes, state);
			pos_changed = false;
		}
		// if doing a two or four byte strategy, check for mutations that could have been produced by
		// previous arith strategies.
		if (substates->current_substrategy > BYTE_ARITH && afl_arith_should_skip_mutation(state, orig_bytes)) {
			afl_arith_update(state);
			continue;
		}
		// invoke the correct substrategy
		switch (substates->current_substrategy) {

		case BYTE_ARITH:
			// perform mutation
			size = substates->det_byte_arith_strategy->mutate(buf, size, substates->det_byte_arith_substate);
			// if substrategy is complete
			if (!size) {
				substates->substrategy_complete = 1;
				size                            = orig_size;
			}
			break;

		case TWO_BYTE_ARITH_LE:
			size = substates->det_two_byte_arith_le_strategy->mutate(buf, size, substates->det_two_byte_arith_le_substate);
			// if substrategy is complete
			if (!size) {
				substates->substrategy_complete = 1;
				size                            = orig_size;
			}
			break;

		case TWO_BYTE_ARITH_BE:
			size = substates->det_two_byte_arith_be_strategy->mutate(buf, size, substates->det_two_byte_arith_be_substate);
			// if substrategy is complete
			if (!size) {
				substates->substrategy_complete = 1;
				size                            = orig_size;
			}
			break;

		case FOUR_BYTE_ARITH_LE:
			size = substates->det_four_byte_arith_le_strategy->mutate(buf, size, substates->det_four_byte_arith_le_substate);
			// if substrategy is complete
			if (!size) {
				substates->substrategy_complete = 1;
				size                            = orig_size;
			}
			break;

		case FOUR_BYTE_ARITH_BE:
			size = substates->det_four_byte_arith_be_strategy->mutate(buf, size, substates->det_four_byte_arith_be_substate);
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
		// size will be zero if all substrategies are complete.
		if (!size)
			return size;
		// if the current substrategy is done, or the mutation is a repeat of a bitflip mutation,
		// restore the original bytes, update the state to the next substrategy, and try mutating again.
		if (substates->substrategy_complete || could_be_bitflip((u32)buf[pos])) {
			afl_arith_copy_bytes(&orig_bytes, (void *)&buf[pos], state);
			afl_arith_update(state);
			continue;
		}
		// if the mutated input is not one that could have been created by the bit flip phase, we're done.
		return size;
	}
	// we shouldn't reach this.
	log_fatal("afl_arith exited mutation loop somehow.");
}

// this function populates a fuzzing_strategy object with afl_arith's function pointers.
void
afl_arith_populate(fuzzing_strategy *strategy)
{
	strategy->version          = VERSION_ONE;
	strategy->name             = "afl_arith";
	strategy->create_state     = afl_arith_create;
	strategy->mutate           = afl_arith;
	strategy->serialize        = afl_arith_serialize;
	strategy->deserialize      = afl_arith_deserialize;
	strategy->print_state      = afl_arith_print;
	strategy->copy_state       = afl_arith_copy;
	strategy->free_state       = afl_arith_free_state;
	strategy->description      = "This strategy combines all of our arith strategies into one single strategy.";
	strategy->update_state     = &afl_arith_update;
	strategy->is_deterministic = true;
}
