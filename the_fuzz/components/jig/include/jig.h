#ifndef JIG_H
#define JIG_H

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
#define VERSION_ONE 1
#define CRASH "crash"
#define HANG "hang"
#define NO_CRASH NULL

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

typedef void(jig_init_function)(void);
typedef char *(jig_run_function)(u8 *input, size_t input_size, u8 **results, size_t *results_size);
typedef void(jig_destroy_function)(void);

typedef struct jig_api {
	int version;
	union {
		struct {
			const char           *name;
			const char           *description;
			jig_init_function    *initialize;
			jig_run_function     *run;
			jig_destroy_function *destroy;
		};
	};
} jig_api;

typedef void (*jig_api_getter)(jig_api *j);

#pragma clang diagnostic pop
extern jig_api_getter    get_jig_api;

#endif
