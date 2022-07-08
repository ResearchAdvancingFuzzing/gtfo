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

#include "common/yaml_helper.h"
#include "strategy.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
    This file contains the methods for the standard strategy_state object
    and the pcg32_state object.
*/

// This function copies a strategy state:9
// note that it does copy the internal_state pointer but zeroes it.
inline strategy_state *
strategy_state_copy(strategy_state *state)
{
	// calloc new object and copy old obj
	strategy_state *new_state = calloc(1, sizeof(strategy_state));
	memcpy(new_state, state, sizeof(strategy_state));

	new_state->internal_state = NULL;

	return new_state;
}

// this function creates a new strategy_state object.
inline strategy_state *
strategy_state_create(u8 *seed, size_t max_size, size_t size,  u8* orig_buff, ...)
{

	strategy_state *new_state = calloc(1, sizeof(strategy_state));

	new_state->version   = 1;
	new_state->iteration = 0;
	new_state->max_size  = max_size;
        new_state->size      = size; 
        new_state->orig_buff = orig_buff;
	memcpy(new_state->seed, seed, 32);

	return new_state;
}

// this function frees a strategy state.
// If an internal state object exists, it should be freed and the pointer should be nulled.
inline void
strategy_state_free(strategy_state *state)
{

	assert(state->internal_state == NULL);
	free(state);
}

// Serialize a strategy state structure.
// Note we ignore the internal state pointer as only the caller knows what it points to.
inline char *
strategy_state_serialize(strategy_state *state, char *name)
{
	yaml_serializer *helper;
	char            *mybuffer;
	size_t           mybuffersize;

	helper = yaml_serializer_init("");

	// Provide a name for humans. The deserializer is not expected to process it.
	YAML_SERIALIZE_STRING_KV(helper, strategy_name, name)

	// This is the version of the yaml file format, not the version of the encoded structure(s).
	// It is possible that they will differ.
	YAML_SERIALIZE_32HEX_KV(helper, file_format_version, 0)

	// Serialization of the strategy_state structure:

	// We also name the structure for readability.
	YAML_SERIALIZE_NEST_MAP(helper, strategy_state)
	YAML_SERIALIZE_START_MAPPING(helper)

	YAML_SERIALIZE_64HEX_KV(helper, version, state->version)
	YAML_SERIALIZE_8HEX_ARRAY(helper, state->seed, seed, 32)
	YAML_SERIALIZE_64HEX_KV(helper, iteration, state->iteration)
	YAML_SERIALIZE_64HEX_KV(helper, max_size, (u64)state->max_size)

	YAML_SERIALIZE_END_MAPPING(helper)
	yaml_serializer_end(helper, &mybuffer, &mybuffersize);

	return mybuffer;
}

// This function deserializes a serialized strategy state.
inline strategy_state *
strategy_state_deserialize(char *s_state_buffer, size_t s_state_buffer_size)
{
	yaml_deserializer *helper = NULL;
	strategy_state    *state  = calloc(1, sizeof(strategy_state));

	helper = yaml_deserializer_init(NULL, s_state_buffer, s_state_buffer_size);

	// Get to the document start
	YAML_DESERIALIZE_PARSE(helper)
	while (helper->event.type != YAML_DOCUMENT_START_EVENT) {
		YAML_DESERIALIZE_EAT(helper)
	}

	// Read the strategy name
	// Currently we just read it without doing anything with it, so its presence is mostly to
	// provide understanding for humands reading the file or perhaps it would be useful when debugging.

	char my_strategy_name[80];
	uint my_file_format_version;

	YAML_DESERIALIZE_EAT(helper)
	YAML_DESERIALIZE_GET_KV_STRING(helper, "strategy_name", my_strategy_name, sizeof(my_strategy_name))
	YAML_DESERIALIZE_GET_KV_U32(helper, "file_format_version", &my_file_format_version)

	// Deserialize the strategy_state structure:
	// This is coded like LL(1) parsing, not event-driven, because we only support one version of file_format_version and
	// no structure members are optional in the yaml file.
	YAML_DESERIALIZE_MAPPING_START(helper, "strategy_state")
	YAML_DESERIALIZE_GET_KV_U64(helper, "version", &state->version)
	YAML_DESERIALIZE_SEQUENCE_U8(helper, "seed", state->seed)
	YAML_DESERIALIZE_GET_KV_U64(helper, "iteration", &state->iteration)
	YAML_DESERIALIZE_GET_KV_U64(helper, "max_size", &state->max_size)
	YAML_DESERIALIZE_MAPPING_END(helper)

	yaml_deserializer_end(helper);

	return state;
}

// this function creates a string containing human-readable status info about a state.
inline char *
strategy_state_print(strategy_state *state, char *strategy_name)
{
	size_t bufsize = 256 + strlen(strategy_name);
	// probably big enough
	char *str_buf = calloc(1, bufsize + 1);

	snprintf(str_buf,
	         bufsize,
	         "Mutation Strategy: %s\n"
	         "Version: %" PRIu64 "\n"
	         "Seed: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n"
	         "Iteration: %" PRIu64 "\n"
	         "Max Size: %zu\n\n",
	         strategy_name,
	         state->version,
	         state->seed[0], state->seed[1], state->seed[2], state->seed[3], state->seed[4],
	         state->seed[5], state->seed[6], state->seed[7], state->seed[8], state->seed[9],
	         state->seed[10], state->seed[11], state->seed[12], state->seed[13], state->seed[14],
	         state->seed[15], state->seed[16], state->seed[17], state->seed[18], state->seed[19],
	         state->seed[20], state->seed[21], state->seed[22], state->seed[23], state->seed[24],
	         state->seed[25], state->seed[26], state->seed[27], state->seed[28], state->seed[29],
	         state->seed[30], state->seed[31],
	         state->iteration,
	         state->max_size);

	return str_buf;
}

// this function updates a standard strategy state
inline void
strategy_state_update(strategy_state *state)
{
	state->iteration++;
}
