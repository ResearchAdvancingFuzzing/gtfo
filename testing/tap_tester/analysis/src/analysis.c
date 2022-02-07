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

#include "analysis.h"
#include "common.h"
#include "tap.h"
#include "testfile.h"

#include <dlfcn.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static analysis_api s;

#define VERSION_ONE_TEST_COUNT_PER_INPUT 2
#define VERSION_ONE_TEST_EXTRA 2
static __attribute__((noreturn)) void
usage(char *arg0)
{
	fprintf(stderr, "Usage: %s -A [analysis engine] -t [test file]\n", arg0);
	exit(EXIT_FAILURE);
}

static void
test_version_one(char *test_filename)
{

	FILE *testfile = fopen(test_filename, "r");
	if (testfile == NULL) {
		bail_out(strerror(errno));
	}

	u64 input_count = count_tests(testfile, 2);
	u64 test_count  = (input_count * VERSION_ONE_TEST_COUNT_PER_INPUT) + VERSION_ONE_TEST_EXTRA;
	plan((unsigned int)test_count);

	char *meta = NULL;
	check_header(testfile, &meta);
	free(meta);
	s.initialize(NULL);

	char *desc      = NULL;
	int   desc_size = 0;
	desc_size       = asprintf(&desc, "Testing %s\n", s.name);
	if (desc_size < 0) {
		bail_out("asprintf failed");
	}
	diagnostics(desc);
	free(desc);
	desc = NULL;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wvla"
	u8    *inputs[input_count];
	size_t inputs_size[input_count];
#pragma clang diagnostic pop

	for (size_t i = 0; i < input_count; i++) {
		char *input_filename = get_line_from_test_file(testfile);
		char *expected       = get_line_from_test_file(testfile);
		char *io_file        = get_io_file(test_filename, input_filename);
		read_file(0, io_file, &(inputs_size[i]), &(inputs[i]));
		if (strcmp("true", expected) == 0) {
			ok(s.add(inputs[i], inputs_size[i]) == true, "attempting to add element");
		} else if (strcmp("false", expected) == 0) {
			ok(s.add(inputs[i], inputs_size[i]) == false, "attempting to add element");
		} else {
			free(input_filename);
			free(io_file);
			free(expected);
			bail_out("unknown expected value");
		}
		free(input_filename);
		free(io_file);
		free(expected);
	}
	// save and reload
	char *save_file = "analysis_save";
	s.save(save_file);
	s.destroy();
	s.initialize(save_file);
	rewind(testfile);
	meta = NULL;
	check_header(testfile, &meta);
	free(meta);

	// make sure everything is still there
	for (size_t i = 0; i < input_count; i++) {
		char *input_filename = get_line_from_test_file(testfile);
		char *expected       = get_line_from_test_file(testfile);
		char *io_file        = get_io_file(test_filename, input_filename);
		ok(s.add(inputs[i], inputs_size[i]) == true, "attempting to add element");
		free(input_filename);
		free(io_file);
		free(expected);
	}

	unlink(save_file);
	for (size_t i = 0; i < input_count; i++) {
		free(inputs[i]);
	}
}

int
main(int argc, char *argv[])
{
	int   opt;
	char *library       = NULL;
	char *test_filename = NULL;

	while ((opt = getopt(argc, argv, "A:t:")) != -1) {
		switch (opt) {
		case 'A':
			if (optarg == NULL) {
				usage(argv[0]);
			}
			library = strdup(optarg);
			break;
		case 't':
			if (optarg == NULL) {
				usage(argv[0]);
			}
			test_filename = strdup(optarg);
			break;
		default:
			usage(argv[0]);
		}
	}

	if (library == NULL || test_filename == NULL) {
		usage(argv[0]);
	}

	print_tap_header();

	void *handle = NULL;
	handle       = dlopen(library, RTLD_LAZY);
	char *error  = dlerror();
	// check that we can open the handle
	if (error) {
		bail_out(error);
	}
	// get function pointer to the function that populates the analysis struct
	analysis_api_getter *get_analysis;
	get_analysis = (analysis_api_getter *)dlsym(handle, "get_analysis_api");
	error        = dlerror();
	if (error) {
		bail_out(error);
	}

	// populate the analysis struct
	(*get_analysis)(&s);

	switch (s.version) {
	case 1:
		test_version_one(test_filename);
		break;
	default:
		plan(1);
		bail_out("Unsupported Version");
		break;
	}
	free(library);
	free(test_filename);
	return 0;
}
