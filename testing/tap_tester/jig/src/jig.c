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

#include "jig.h"
#include "tap.h"
#include "testfile.h"
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wused-but-marked-unused"

static jig_api j;

#define VERSION_ONE_TESTS 1
static void __attribute__((noreturn))
usage(char *arg0)
{
	fprintf(stderr, "Usage: %s -J [jig] -t [test file]\n", arg0);
	exit(EXIT_FAILURE);
}

static void
test_version_one(char *test_filename)
{
	int chdir_status = chdir(testfile_dir(test_filename));
	if (chdir_status < 0) {
		bail_out("chdir failed");
	}
	char *cwd = get_current_dir_name();
	free(cwd);

	FILE *testfile = fopen(test_filename, "r");
	if (testfile == NULL) {
		bail_out(strerror(errno));
	}

	u64 test_count = (count_tests(testfile, 3) * 5) + VERSION_ONE_TESTS;

	plan((unsigned int)test_count);

	char *meta = NULL;
	check_header(testfile, &meta);

	free(meta);
	char *diag      = NULL;
	int   diag_size = 0;
	diag_size       = asprintf(&diag, "Testing %s", j.name);
	if (diag_size < 0) {
		bail_out("asprintf failed");
	}
	diagnostics(diag);
	free(diag);
	diag = NULL;

	u8 *   results      = NULL;
	size_t results_size = 0;
	j.initialize();
	while (1) {
		char * input_filename = NULL;
		u8 *   input          = NULL;
		size_t input_size     = 0;

		char * output_filename = NULL;
		u8 *   output          = NULL;
		size_t output_size     = 0;

		char *run_output = NULL;

		char *input_filename_rel = get_line_from_test_file(testfile);
		if (input_filename_rel == NULL) {
			break;
		}
		char *output_filename_rel = get_line_from_test_file(testfile);
		if (output_filename_rel == NULL) {
			bail_out("testfile corrupt");
		}
		run_output = get_line_from_test_file(testfile);
		if (run_output == NULL) {
			bail_out("testfile corrupt");
		}
		input_filename  = get_io_file(test_filename, input_filename_rel);
		output_filename = get_io_file(test_filename, output_filename_rel);
		free(input_filename_rel);
		free(output_filename_rel);

		read_file(0, input_filename, &input_size, &input);
		read_file(0, output_filename, &output_size, &output);

		char *run_results = j.run(input, input_size, &results, &results_size);

		ok(results_size == output_size, "size check");
		ok(memcmp(results, output, output_size) == 0, "results check");

		if (run_results == NULL) {
			ok(!strncmp(run_output, "NULL", 4), "status_check");
		} else {
			size_t len = 0;
			for (; len < strlen(run_output); len++) {
				if (run_output[len] == '\n') {
					break;
				}
			}
			ok(strncmp(run_output, run_results, len) == 0, "status check");
		}

		j.run(input, input_size, &results, &results_size);

		ok(results_size == output_size, "size check, second run");
		ok(memcmp(results, output, output_size) == 0, "results check, second run");

		free(input_filename);
		free(input);
		free(output_filename);
		free(output);
		free(run_output);
	}
	j.destroy();
}

int
main(int argc, char *argv[])
{
	int   opt           = 0;
	char *library       = NULL;
	char *test_filename = NULL;
	while ((opt = getopt(argc, argv, "J:t:")) != -1) {
		switch (opt) {
		case 'J':
			library = strdup(optarg);
			break;
		case 't':
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

	jig_api_getter *get_jig;
	get_jig = (jig_api_getter *)dlsym(handle, "get_jig_api");
	error   = dlerror();
	if (error) {
		bail_out(error);
	}

	(*get_jig)(&j);

	switch (j.version) {
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
#pragma clang diagnostic pop
