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
#include <stdbool.h>
#define VERSION_ONE 1

typedef bool(analysis_add_function)(u8 *element, size_t element_size);
typedef void(analysis_init_function)(char *filename);
typedef void(analysis_save_function)(char *filename);
typedef void(analysis_destroy_function)(void);
typedef void(analysis_merge_function)(char *a, char *b, char *merged);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
typedef struct analysis_api {
	int version;
	union {
		struct {
			const char *               name;
			const char *               description;
			analysis_init_function *   initialize;
			analysis_add_function *    add; // This returns true if the results have been seen before
			analysis_save_function *   save;
			analysis_destroy_function *destroy;
			analysis_merge_function *  merge;
		};
	};
} analysis_api;
#pragma clang diagnostic pop

typedef void (*analysis_api_getter)(analysis_api *s);

extern analysis_api_getter get_analysis_api;
