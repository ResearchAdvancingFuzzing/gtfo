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

#include <stdlib.h>
#include <stdio.h>
#include <yaml.h>
#include <signal.h>
#include <inttypes.h>
//#include "common.h"

typedef struct yaml_serializer {
	yaml_emitter_t emitter;
	yaml_event_t   event;
	char          *outfile_name;
	FILE          *outfile;
	char          *memstream_buffer;
	size_t         memstream_buffer_size;
} yaml_serializer;

#define YAML_EMIT(HELPER)                                                                        \
	do {                                                                                         \
		if (!yaml_emitter_emit(&(HELPER)->emitter, &(HELPER)->event)) {                          \
			log_fatal("libyaml failed %d: %s", (HELPER)->event.type, (HELPER)->emitter.problem); \
		}                                                                                        \
	} while (0);

#define YAML_SERIALIZE_INIT(HELPER)                                                  \
	do {                                                                             \
		yaml_emitter_initialize(&(HELPER)->emitter);                                 \
		yaml_emitter_set_output_file(&(HELPER)->emitter, (HELPER)->outfile);         \
		yaml_stream_start_event_initialize(&(HELPER)->event, YAML_UTF8_ENCODING);    \
		YAML_EMIT(HELPER)                                                            \
		yaml_document_start_event_initialize(&(HELPER)->event, NULL, NULL, NULL, 0); \
		YAML_EMIT(HELPER)                                                            \
	} while (0);

#define YAML_SERIALIZE_END(HELPER)                               \
	do {                                                         \
		yaml_document_end_event_initialize(&(HELPER)->event, 0); \
		YAML_EMIT(HELPER)                                        \
		yaml_stream_end_event_initialize(&(HELPER)->event);      \
		YAML_EMIT(HELPER)                                        \
		yaml_emitter_delete(&(HELPER)->emitter);                 \
		yaml_event_delete(&(HELPER)->event);                     \
	} while (0);

#define YAML_SERIALIZE_START_MAPPING(HELPER)                                                                                 \
	do {                                                                                                                     \
		yaml_mapping_start_event_initialize(&(HELPER)->event, NULL, (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE); \
		YAML_EMIT(HELPER);                                                                                                   \
	} while (0);

#define YAML_SERIALIZE_END_MAPPING(HELPER)                   \
	do {                                                     \
		yaml_mapping_end_event_initialize(&(HELPER)->event); \
		YAML_EMIT(HELPER);                                   \
	} while (0);

#define YAML_SERIALIZE_SEQ_BEGIN(HELPER)                                                                                       \
	do {                                                                                                                       \
		yaml_sequence_start_event_initialize(&(HELPER)->event, NULL, (yaml_char_t *)YAML_SEQ_TAG, 1, YAML_ANY_SEQUENCE_STYLE); \
		YAML_EMIT(HELPER);                                                                                                     \
	} while (0);

#define YAML_SERIALIZE_SEQ_END(HELPER)                        \
	do {                                                      \
		yaml_sequence_end_event_initialize(&(HELPER)->event); \
		YAML_EMIT(HELPER);                                    \
	} while (0);

#define YAML_SERIALIZE_NEST_MAP(HELPER, NAME)                                                                                                                  \
	do {                                                                                                                                                       \
		yaml_scalar_event_initialize(&(HELPER)->event, NULL, (yaml_char_t *)YAML_STR_TAG, (yaml_char_t *)#NAME, strlen(#NAME), 1, 0, YAML_PLAIN_SCALAR_STYLE); \
		YAML_EMIT(HELPER);                                                                                                                                     \
	} while (0);

/* BEGIN HELPER MACROS */
#define YAML_SERIALIZE_XHEX_TSTRUCT(HELPER, STRUCT, MEM, WIDTH, TYPE_OP)                                                                                              \
	do {                                                                                                                                                              \
		yaml_scalar_event_initialize(&(HELPER)->event, NULL, (yaml_char_t *)YAML_STR_TAG, (yaml_char_t *)#MEM, strlen(#MEM), 1, 0, YAML_PLAIN_SCALAR_STYLE);          \
		YAML_EMIT(HELPER);                                                                                                                                            \
		char *buffer = NULL;                                                                                                                                          \
		asprintf(&buffer, "%" WIDTH, STRUCT TYPE_OP MEM);                                                                                                             \
		yaml_scalar_event_initialize(&(HELPER)->event, NULL, (yaml_char_t *)YAML_INT_TAG, (yaml_char_t *)buffer, (int)strlen(buffer), 1, 0, YAML_PLAIN_SCALAR_STYLE); \
		YAML_EMIT(HELPER);                                                                                                                                            \
		free(buffer);                                                                                                                                                 \
	} while (0);
// helper for array serialization
#define YAML_SERIALIZE_XHEX_ARRAY(HELPER, ARRAY, NAME, SIZE, WIDTH)                                                                                                       \
	do {                                                                                                                                                                  \
		yaml_scalar_event_initialize(&(HELPER)->event, NULL, (yaml_char_t *)YAML_STR_TAG, (yaml_char_t *)#NAME, (int)strlen(#NAME), 1, 0, YAML_PLAIN_SCALAR_STYLE);       \
		YAML_EMIT(HELPER);                                                                                                                                                \
		YAML_SERIALIZE_SEQ_BEGIN(HELPER);                                                                                                                                 \
		char *buffer = NULL;                                                                                                                                              \
		for (size_t seq_j = 0; seq_j < (SIZE); seq_j++) {                                                                                                                 \
			asprintf(&buffer, "%" WIDTH, (ARRAY)[seq_j]);                                                                                                                 \
			yaml_scalar_event_initialize(&(HELPER)->event, NULL, (yaml_char_t *)YAML_INT_TAG, (yaml_char_t *)buffer, (int)strlen(buffer), 1, 0, YAML_PLAIN_SCALAR_STYLE); \
			YAML_EMIT(HELPER);                                                                                                                                            \
			free(buffer);                                                                                                                                                 \
			buffer = NULL;                                                                                                                                                \
		}                                                                                                                                                                 \
		YAML_SERIALIZE_SEQ_END(HELPER);                                                                                                                                   \
	} while (0);

// helper for KEY/VALUE Serialization
#define YAML_SERIALIZE_XHEX_KV(HELPER, KEY, VALUE, WIDTH)                                                                                                             \
	do {                                                                                                                                                              \
		yaml_scalar_event_initialize(&(HELPER)->event, NULL, (yaml_char_t *)YAML_STR_TAG, (yaml_char_t *)#KEY, strlen(#KEY), 1, 0, YAML_PLAIN_SCALAR_STYLE);          \
		YAML_EMIT(HELPER);                                                                                                                                            \
		char *buffer = NULL;                                                                                                                                          \
		asprintf(&buffer, "%" WIDTH, VALUE);                                                                                                                          \
		yaml_scalar_event_initialize(&(HELPER)->event, NULL, (yaml_char_t *)YAML_INT_TAG, (yaml_char_t *)buffer, (int)strlen(buffer), 1, 0, YAML_PLAIN_SCALAR_STYLE); \
		YAML_EMIT(HELPER);                                                                                                                                            \
		free(buffer);                                                                                                                                                 \
	} while (0);
/* END HELPER MACROS */
// serialization macros that take a pointer to a struct
#define YAML_SERIALIZE_64HEX_PSTRUCT(HELPER, STRUCT, MEM) YAML_SERIALIZE_XHEX_TSTRUCT(HELPER, STRUCT, MEM, PRIx64, ->)
#define YAML_SERIALIZE_32HEX_PSTRUCT(HELPER, STRUCT, MEM) YAML_SERIALIZE_XHEX_TSTRUCT(HELPER, STRUCT, MEM, PRIx32, ->)
#define YAML_SERIALIZE_16HEX_PSTRUCT(HELPER, STRUCT, MEM) YAML_SERIALIZE_XHEX_TSTRUCT(HELPER, STRUCT, MEM, PRIx16, ->)
#define YAML_SERIALIZE_8HEX_PSTRUCT(HELPER, STRUCT, MEM) YAML_SERIALIZE_XHEX_TSTRUCT(HELPER, STRUCT, MEM, PRIx8, ->)

// serialization macros that take a struct
#define YAML_SERIALIZE_64HEX_STRUCT(HELPER, STRUCT, MEM) YAML_SERIALIZE_XHEX_TSTRUCT(HELPER, STRUCT, MEM, PRIx64, .)
#define YAML_SERIALIZE_32HEX_STRUCT(HELPER, STRUCT, MEM) YAML_SERIALIZE_XHEX_TSTRUCT(HELPER, STRUCT, MEM, PRIx32, .)
#define YAML_SERIALIZE_16HEX_STRUCT(HELPER, STRUCT, MEM) YAML_SERIALIZE_XHEX_TSTRUCT(HELPER, STRUCT, MEM, PRIx16, .)
#define YAML_SERIALIZE_8HEX_STRUCT(HELPER, STRUCT, MEM) YAML_SERIALIZE_XHEX_TSTRUCT(HELPER, STRUCT, MEM, PRIx8, .)

// serialziation macros that take a key/value pair
#define YAML_SERIALIZE_64HEX_KV(HELPER, KEY, VALUE) YAML_SERIALIZE_XHEX_KV(HELPER, KEY, VALUE, PRIx64)
#define YAML_SERIALIZE_32HEX_KV(HELPER, KEY, VALUE) YAML_SERIALIZE_XHEX_KV(HELPER, KEY, VALUE, PRIx32)
#define YAML_SERIALIZE_16HEX_KV(HELPER, KEY, VALUE) YAML_SERIALIZE_XHEX_KV(HELPER, KEY, VALUE, PRIx16)
#define YAML_SERIALIZE_8HEX_KV(HELPER, KEY, VALUE) YAML_SERIALIZE_XHEX_KV(HELPER, KEY, VALUE, PRIx8)
#define YAML_SERIALIZE_1HEX_KV(HELPER, KEY, VALUE)  \
	do {                                            \
		uint8_t foo = VALUE;                        \
		YAML_SERIALIZE_8HEX_KV((HELPER), KEY, foo); \
	} while (0);

// serialization macros that take an array of n_byte values
#define YAML_SERIALIZE_64HEX_ARRAY(HELPER, ARRAY, NAME, SIZE) YAML_SERIALIZE_XHEX_ARRAY(HELPER, ARRAY, NAME, SIZE, PRIx64)
#define YAML_SERIALIZE_32HEX_ARRAY(HELPER, ARRAY, NAME, SIZE) YAML_SERIALIZE_XHEX_ARRAY(HELPER, ARRAY, NAME, SIZE, PRIx32)
#define YAML_SERIALIZE_16HEX_ARRAY(HELPER, ARRAY, NAME, SIZE) YAML_SERIALIZE_XHEX_ARRAY(HELPER, ARRAY, NAME, SIZE, PRIx16)
#define YAML_SERIALIZE_8HEX_ARRAY(HELPER, ARRAY, NAME, SIZE) YAML_SERIALIZE_XHEX_ARRAY(HELPER, ARRAY, NAME, SIZE, PRIx8)

// Serialize a string
#define YAML_SERIALIZE_STRING_KV(HELPER, KEY, VALUE)                                                                                                                    \
	do {                                                                                                                                                                \
		yaml_scalar_event_initialize(&(HELPER)->event, NULL, (yaml_char_t *)YAML_STR_TAG, (yaml_char_t *)#KEY, strlen(#KEY), 1, 0, YAML_PLAIN_SCALAR_STYLE);            \
		YAML_EMIT(HELPER);                                                                                                                                              \
		yaml_scalar_event_initialize(&(HELPER)->event, NULL, (yaml_char_t *)YAML_STR_TAG, (yaml_char_t *)(VALUE), (int)strlen((VALUE)), 1, 0, YAML_PLAIN_SCALAR_STYLE); \
		YAML_EMIT(HELPER);                                                                                                                                              \
	} while (0);

#define YAML_SERIALIZE_STRUCT_ARRAY(HELPER, ARRAY, NAME, SIZE, STRUCT_SERIALIZER_FUNCTION)                                                                     \
	do {                                                                                                                                                       \
		yaml_scalar_event_initialize(&(HELPER)->event, NULL, (yaml_char_t *)YAML_STR_TAG, (yaml_char_t *)#NAME, strlen(#NAME), 1, 0, YAML_PLAIN_SCALAR_STYLE); \
		YAML_EMIT(HELPER);                                                                                                                                     \
		YAML_SERIALIZE_SEQ_BEGIN(HELPER);                                                                                                                      \
		for (size_t seq_i = 0; seq_i < (SIZE); seq_i++) {                                                                                                      \
			STRUCT_SERIALIZER_FUNCTION((HELPER), (ARRAY)[seq_i]);                                                                                              \
		}                                                                                                                                                      \
		YAML_SERIALIZE_SEQ_END(HELPER);                                                                                                                        \
	} while (0);
