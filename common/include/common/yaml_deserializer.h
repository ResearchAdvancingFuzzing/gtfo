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
#include "common.h"

// helper object for managing structs needed for deserialization
typedef struct yaml_deserializer {
	yaml_parser_t parser;
	yaml_event_t  event;
	char *        infile_name;
	FILE *        infile;
        char *        buffer;
        size_t        buffer_size;
} yaml_deserializer;

// get a yaml_event_t token
#define YAML_DESERIALIZE_PARSE(HELPER)                              \
	do {                                                        \
		yaml_parser_parse(&(HELPER)->parser, &(HELPER)->event); \
	} while (0);

// clear the yaml_event_t struct in yaml_deserializer.
#define YAML_DESERIALIZE_EVENT_DELETE(HELPER)      \
	do {                                       \
		yaml_event_delete(&(HELPER)->event); \
	} while (0);

#define YAML_DESERIALIZE_EAT(HELPER)                   \
	do {                                           \
		YAML_DESERIALIZE_EVENT_DELETE(HELPER); \
		YAML_DESERIALIZE_PARSE(HELPER);        \
	} while (0);

// get next event, and strcmp with provided string
#define YAML_DESERIALIZE_STRCMP(HELPER, STR, RETVAL)                           \
	do {                                                                   \
		YAML_DESERIALIZE_EAT(HELPER);                                  \
        (RETVAL) = strcmp((char *)(HELPER)->event.data.scalar.value, STR); \
	} while (0);

// deserialize a scalar value
#define YAML_DESERIALIZE_SCALAR_UX(HELPER, DEST, FMT)                                   \
	do {                                                                            \
		YAML_DESERIALIZE_EAT(HELPER);                                           \
		if ((HELPER)->event.type == YAML_SCALAR_EVENT) {                        \
			sscanf((char *)(HELPER)->event.data.scalar.value, "%" FMT, DEST); /*NOLINT(cert-err34-c)*/ \
		}                                                                       \
	} while (0);

// given a key, deserialize a value
#define YAML_DESERIALIZE_GET_KV_UX(HELPER, KEY, DEST, FMT)                                          \
	do {                                                                                        \
		int retval = 0;                                                                     \
		YAML_DESERIALIZE_STRCMP(HELPER, KEY, retval);                                       \
		if (!retval) {                                                                      \
			YAML_DESERIALIZE_SCALAR_UX(HELPER, DEST, FMT);                              \
		} else {                                                                            \
			log_fatal("key '%s' for GET_KV mismatch (%s:%d)", KEY, __func__, __LINE__); \
		}                                                                                   \
	} while (0);

// given a key, deserialize a string with a maximum length
//		sscanf((char *)(HELPER)->event.data.scalar.value, (const char *)format, DEST); /*NOLINT(cert-err34-c)*/
#define YAML_DESERIALIZE_GET_KV_STRING(HELPER, KEY, DEST, LENGTH)		                    \
  do {									                            \
          int retval; 							                            \
          char format[10];						                            \
          sprintf(format, "%%%ds", (int) LENGTH-1);   				                    \
	  YAML_DESERIALIZE_STRCMP(HELPER, KEY, retval);                                             \
          if (!retval) {					                                    \
		YAML_DESERIALIZE_EAT(HELPER); 			                                    \
		_Pragma ("clang diagnostic push")				                    \
		_Pragma ("clang diagnostic ignored \"-Wformat-nonliteral\"")                        \
		sscanf((char *)(HELPER)->event.data.scalar.value, format, DEST);                    \
		_Pragma ("clang diagnostic pop")			                            \
	  } else {                                                                                  \
		log_fatal("key '%s' for GET_KV mismatch (%s:%d)", KEY, __func__, __LINE__);         \
	  }                                                                                         \
	} while (0);


// wrappers for various value sizes
#define YAML_DESERIALIZE_GET_KV_U8(HELPER, KEY, DEST) YAML_DESERIALIZE_GET_KV_UX(HELPER, KEY, DEST, SCNx8)
#define YAML_DESERIALIZE_GET_KV_U16(HELPER, KEY, DEST) YAML_DESERIALIZE_GET_KV_UX(HELPER, KEY, DEST, SCNx16)
#define YAML_DESERIALIZE_GET_KV_U32(HELPER, KEY, DEST) YAML_DESERIALIZE_GET_KV_UX(HELPER, KEY, DEST, SCNx32)
#define YAML_DESERIALIZE_GET_KV_U64(HELPER, KEY, DEST) YAML_DESERIALIZE_GET_KV_UX(HELPER, KEY, DEST, SCNx64)

// more wrapperz
#define YAML_DESERIALIZE_SCALAR_U8(HELPER, DEST) YAML_DESERIALIZE_SCALAR_UX(HELPER, DEST, SCNx8)
#define YAML_DESERIALIZE_SCALAR_U16(HELPER, DEST) YAML_DESERIALIZE_SCALAR_UX(HELPER, DEST, SCNx16)
#define YAML_DESERIALIZE_SCALAR_U32(HELPER, DEST) YAML_DESERIALIZE_SCALAR_UX(HELPER, DEST, SCNx32)
#define YAML_DESERIALIZE_SCALAR_U64(HELPER, DEST) YAML_DESERIALIZE_SCALAR_UX(HELPER, DEST, SCNx64)

#define YAML_DESERIALIZE_GET_KV_U1(HELPER, KEY, DEST)             \
	do {                                                      \
		u8  foo = 0;                                      \
		int r   = 0;                                      \
		YAML_DESERIALIZE_STRCMP(HELPER, KEY, r);          \
		if (!r) {                                         \
			YAML_DESERIALIZE_SCALAR_U8(HELPER, &foo); \
            (DEST) = foo;                                         \
		}                                                 \
	} while (0);

// Deserialize a sequence from start to finish, calling DESERIALIZE_FUNC on each entry in said sequence.
//
// A sequence is a series of "objects" surrounded by a sequence_start/sequence_end pair.
// The objects may be as simple as a series of scalars or as complicated as a series of
// mapping_start/mapping_end pairs surrounding another collection of objects.
//
// Because of this macro does not know what to expect, it loops calling the supplied DESERIALIZE_FUNC until
// the most recent event is the sequence_end event. The DESERIALIZE_FUNC must read any mapping_start/_end
// pairs as well as just return when it reads the sequence_end event.

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#define YAML_DESERIALIZE_SEQUENCE(HELPER, KEY, DESERIALIZE_FUNC, DEST, ...)                                 \
	do {                                                                                                \
		int retval = 0;                                                                             \
		u64 pos    = 0;                                                                             \
                                                                                                            \
		YAML_DESERIALIZE_STRCMP(HELPER, KEY, retval); /* confirm the key */                         \
		if (retval) {                                                                               \
			log_fatal("sequencing key '%s' missing|mismatch (%s:%d)", KEY, __func__, __LINE__); \
		}                                                                                           \
                                                                                                            \
		YAML_DESERIALIZE_EAT(HELPER); /* eat the sequence_start */                                  \
		if ((HELPER)->event.type != YAML_SEQUENCE_START_EVENT) {                                    \
			log_fatal("event type %d != YAML_SEQUENCE_START_EVENT for key '%s' (%s:%d)",        \
			          (int)(HELPER)->event.type, KEY, __func__, __LINE__);                      \
		}                                                                                           \
                                                                                                            \
		while ((HELPER)->event.type != YAML_SEQUENCE_END_EVENT) {                                   \
		  DESERIALIZE_FUNC((HELPER), &(DEST)[pos], ##__VA_ARGS__);                                  \
			pos++;                                                                              \
		}                                                                                           \
	} while (0);
#pragma clang diagnostic pop

#define YAML_DESERIALIZE_SEQUENCE_U8(HELPER, KEY, DEST) YAML_DESERIALIZE_SEQUENCE(HELPER, KEY, YAML_DESERIALIZE_SCALAR_U8, DEST)
#define YAML_DESERIALIZE_SEQUENCE_U16(HELPER, KEY, DEST) YAML_DESERIALIZE_SEQUENCE(HELPER, KEY, YAML_DESERIALIZE_SCALAR_U16, DEST)
#define YAML_DESERIALIZE_SEQUENCE_U32(HELPER, KEY, DEST) YAML_DESERIALIZE_SEQUENCE(HELPER, KEY, YAML_DESERIALIZE_SCALAR_U32, DEST)
#define YAML_DESERIALIZE_SEQUENCE_U64(HELPER, KEY, DEST) YAML_DESERIALIZE_SEQUENCE(HELPER, KEY, YAML_DESERIALIZE_SCALAR_U64, DEST)

// Macro for starting the deserialization of a mapping
#define YAML_DESERIALIZE_MAPPING_START(HELPER, KEY)                                                     \
	do {                                                                                            \
		int retval = 0;                                                                         \
		YAML_DESERIALIZE_STRCMP(HELPER, KEY, retval);                                           \
		if (!retval) {                                                                          \
			YAML_DESERIALIZE_EAT(HELPER);                                                   \
			if ((HELPER)->event.type != YAML_MAPPING_START_EVENT) {                         \
				log_fatal("event type %d != YAML_MAPPING_START_EVENT (%s:%d)",          \
				          (int)(HELPER)->event.type, __func__, __LINE__);               \
			}                                                                               \
		} else {                                                                                \
			log_fatal("mapping key '%s' start mismatch! (%s:%d)", KEY, __func__, __LINE__); \
		}                                                                                       \
	} while (0);

// Macro for ending the deserialization of a mapping
#define YAML_DESERIALIZE_MAPPING_END(HELPER)                                         \
	do {                                                                         \
		YAML_DESERIALIZE_EAT(HELPER);                                        \
		if ((HELPER)->event.type != YAML_MAPPING_END_EVENT) {                \
			log_fatal("event type %d != YAML_MAPPING_END_EVENT (%s:%d)", \
			          (int)(HELPER)->event.type, __func__, __LINE__);    \
		}                                                                    \
	} while (0);
