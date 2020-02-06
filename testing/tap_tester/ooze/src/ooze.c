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

#include "ooze.h"
#include "tap.h"
#include "testfile.h"
#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VERSION_ONE_TESTS 4

static fuzzing_strategy strategy;
static FILE *           test_file;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wused-but-marked-unused"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-parameter"
#pragma GCC diagnostic ignored "-Wunused-parameter"

static void
iteration_check(int multiplier __attribute__((unused)), int fudge __attribute__((unused)))
{
	todo("I need to implement the iteration check.");
}

static void
check_mutation(char *serialized_begin_state, size_t serialized_begin_state_size, u8 *input, size_t input_size, u8 *output, size_t output_size)
{
	int              retval              = 0;
	size_t           mutated_size        = 0;
	char            *diagnostics_buffer  = NULL;
	strategy_state  *deserialized_state = (*strategy.deserialize)(serialized_begin_state, serialized_begin_state_size);
	char            *reserialized_state = (*strategy.serialize)(deserialized_state);

	// Test the strategy.serialize function, ensuring that the serialized state
	// matches the one provided in the test file
	if (memcmp(serialized_begin_state, reserialized_state, serialized_begin_state_size) == 0) {
		ok(true, "The state is correctly serialized and deserialized.");
	} else {
		ok(false, "The state is incorrectly serialized and deserialized.");

		size_t first_diff = 0;
		for (size_t i = 0; i < serialized_begin_state_size; i++) {
			if (serialized_begin_state[i] != reserialized_state[i]) {
				first_diff = i;
				break;
			}
		}
		retval = asprintf(&diagnostics_buffer, "First Difference at: %zu\n%s\n%s", first_diff, serialized_begin_state, reserialized_state);
		if (retval < 0) {
			fprintf(stderr, "asprintf failed near line %d\n", __LINE__);
		}
		diagnostics(diagnostics_buffer);
		free(diagnostics_buffer);
		diagnostics_buffer = NULL;
	}
	u8 *mutated = calloc(1, deserialized_state->max_size);
	memcpy(mutated, input, input_size);

	// do mutation, return size of newly mutated buffer
	// char * input has been mutated.
	mutated_size = (*strategy.mutate)(mutated, input_size, deserialized_state);
	// check that char * input matches the expected output
	bool debug          = false;
	int  compare_result = 1;
	if (mutated_size != 0) {
		ok(mutated_size == output_size, "size check");
		if (mutated_size != output_size) {
			debug = true;
		}
		compare_result = memcmp(mutated, output, mutated_size);
		ok(compare_result == 0, "mutation check");
		if (compare_result != 0) {
			debug = true;
		}
	} else {
		ok(input_size == output_size, "size check");
		if (input_size != output_size) {
			debug = true;
		}
		compare_result = memcmp(mutated, output, mutated_size) != 0 || memcmp(mutated, input, input_size)  != 0;
		ok(compare_result == 0, "mutation check");
		if (compare_result != 0) {
			debug = true;
		}
	}

	// if input was not correctly mutated, do debug printing.
	if (debug) {

		u8 *  mutated_ptr   = mutated;
		u8 *  output_ptr    = output;
		u8 *  input_ptr     = input;
		char *printed_state = (*(print_state *)strategy.print_state)(deserialized_state);
		diagnostics(printed_state);
		free(printed_state);

		retval = asprintf(&diagnostics_buffer, "Iteration count: %" PRIu64 ", input size: %zu, expected mutated size: %zu, our output size: %zu, max size: %zu, memcmp results: %d\n", deserialized_state->iteration, input_size, mutated_size, output_size, deserialized_state->max_size, compare_result);
		if (retval < 0) {
			fprintf(stderr, "asprintf failed near line %d\n", __LINE__);
		}
		diagnostics(diagnostics_buffer);
		free(diagnostics_buffer);
		diagnostics_buffer = NULL;
		size_t i           = 0;
		diagnostics("Mutated Output - Expected Output - Original Input");
		while (i < deserialized_state->max_size) {
			retval = asprintf(&diagnostics_buffer, "pos %lu: 0x%02x - 0x%02x - 0x%02x", i, (unsigned int)*mutated_ptr++, (unsigned int)*output_ptr++, (unsigned int)*input_ptr++);
			if (retval < 0) {
				fprintf(stderr, "asprintf failed near line %d\n", __LINE__);
			}
			diagnostics(diagnostics_buffer);
			free(diagnostics_buffer);
			diagnostics_buffer = NULL;
			i++;
		}
	}

	// check that no state is left over
	bool         stateless = true;
	unsigned int i;
	for (i = 0; i < 8; i++) {
	        memset(mutated, 0, deserialized_state->max_size);
		memcpy(mutated, input, input_size);
		mutated_size = (*strategy.mutate)(mutated, input_size, deserialized_state);
		if (memcmp(mutated, output, mutated_size) != 0) {
			stateless = false;
			break;
		}
	}
	ok(stateless, "Checking that the mutation is stateless between runs");

	(*(free_state *)strategy.free_state)(deserialized_state);
	free(reserialized_state);
	free(mutated);
}

static void
check_iteration(char *iteration_line)
{
	// get everything from the string, up to the first " "
	char *part = strtok(iteration_line, " ");

	// if the strategy is nondeterministic
	if (!strcmp(part, "inf")) {

		ok(strategy.is_deterministic == false, "Strategy is not deterministic.");
		skip("The strategy is has infinite output so iteration check does not apply.");
	}
	// The strategy is deterministic
	else if (!strcmp(part, "det")) {

		int multiplier = 0;
		int fudge      = 0;

		ok(strategy.is_deterministic, "Strategy is deterministic.");

		part = strtok(NULL, " ");

		if (!part) {
			bail_out("The iteration line is malformed.");
		} else {
			multiplier = (int)strtoul(part, NULL, 0);
		}

		part = strtok(NULL, " ");

		if (!part) {
			bail_out("The iteration line is malformed.");
		} else {
			fudge = (int)strtoul(part, NULL, 0);
		}
		// not implemented
		iteration_check(multiplier, fudge);
	} else {
		bail_out("It appears the test file is missing the det/inf line.");
	}
}

static void
test_version_one_strategy(char *testfile_name)
{
	int retval = 0;
	// Prints the TAP (Test Anything Protocol) Version
	print_tap_header();

	// record the number of tests to perform
	plan((unsigned int)(count_tests(test_file, 3) * 4 + VERSION_ONE_TESTS));

	// Check that the version field of the strategy struct is correct
	ok(strategy.version == VERSION_ONE, "The correct version number has been set in the fuzzing_strategy struct.");

	// get the iteration line.
	char *iter_line = NULL;
	check_header(test_file, &iter_line);

	if (!iter_line) {
		bail_out("Could not get the third line (ITER) of the test file!");
	}
	check_iteration(iter_line);
	free(iter_line);

	// Iterate on performing tests:
	// Each test consists of 3 configuration lines in the test_file.
	while (1) {

		// Line 1: Filename of serialized strategy beginning state data structure(s)
		char           *begin_state_file_rel         = get_line_from_test_file(test_file);

		// Check for end of configuration file
		if (!begin_state_file_rel) {
		  break;
		}

		char           *begin_state_file_name        = get_io_file(testfile_name, begin_state_file_rel);
		char           *serialized_begin_state       = NULL;
		size_t          serialized_begin_state_size  = 0;
		strategy_state *deserialized_begin_state     = NULL;

		if (!begin_state_file_name) {
			bail_out("Test file has the wrong number of lines.");
		}

		read_file(0, begin_state_file_name, &serialized_begin_state_size, (u8 **)&serialized_begin_state);

		deserialized_begin_state = (*strategy.deserialize)(serialized_begin_state, serialized_begin_state_size);

		free(begin_state_file_rel);
		free(begin_state_file_name);


		// Line 2: Filename for input data to mutate
		char  *input_file_rel   = get_line_from_test_file(test_file);
		char  *input_file_name  = get_io_file(testfile_name, input_file_rel);
		u8    *input_data       = NULL;
		size_t input_data_size  = 0;

		if (!input_file_name) {
			bail_out("Test file has the wrong number of lines.");
		}

		read_file(deserialized_begin_state->max_size, input_file_name, &input_data_size, &input_data);

	        free(input_file_rel);
		free(input_file_name);


		// Line 3: Filename for what the mutated output should be
		char  *output_file_rel    = get_line_from_test_file(test_file);
		char  *output_file_name   = get_io_file(testfile_name, output_file_rel);
		u8    *mutated_data       = NULL;
		size_t mutated_data_size  = 0;


		if (output_file_name == NULL) {
			bail_out("Test file has the wrong number of lines.");
		}

		read_file(deserialized_begin_state->max_size, output_file_name, &mutated_data_size, &mutated_data);

		char *diag;
		retval = asprintf(&diag, "Running test %s", output_file_name);
		if (retval < 0) {
			fprintf(stderr, "asprintf failed near line %d\n", __LINE__);
		}
		diagnostics(diag);
		free(diag);

		free(output_file_rel);
		free(output_file_name);


		// Evaluate the mutation
		check_mutation(serialized_begin_state, serialized_begin_state_size, input_data, (size_t)input_data_size, mutated_data, (size_t)mutated_data_size);

		(*(free_state *)strategy.free_state)(deserialized_begin_state);
		free(serialized_begin_state);
		free(input_data);
		free(mutated_data);
	}
}

int
main(int argc, char *argv[])
{
	if (argc != 3) {
		fprintf(stderr, "Usage: %s [mutation strategy] [test file]\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	int   retval = 0;
	void *handle = NULL;

	// Load the fuzzing strategy .so
	handle       = dlopen(argv[1], RTLD_LAZY);
	char *error = dlerror();
	// check that we can open the handle
	if (error) {
		bail_out(error);
	}

	// Get function pointer to the function that populates the fuzzing_strategy struct
	get_fuzzing_strategy_function *get_fuzzing_strat;
	get_fuzzing_strat = (get_fuzzing_strategy_function *)dlsym(handle, "get_fuzzing_strategy");
	error = dlerror();
	if (error) {
		bail_out(error);
	}

	// Populate the fuzzing_strategy plugin functions struct
	(*get_fuzzing_strat)(&strategy);

	// Open the test file containing the list of fuzzing tests for this strategy
	test_file = fopen(argv[2], "r");
	if (!test_file) {
		retval = asprintf(&error, "fopen errored! %s\n", strerror(errno));
		if (retval < 0) {
			fprintf(stderr, "asprintf failed near line %d\n", __LINE__);
		}
		bail_out(error);
	}

	// test the strategy
	switch (strategy.version) {

	    case VERSION_ONE:
		test_version_one_strategy(argv[2]);
		break;
	    default:
		bail_out("Unknown Strategy Version");
	}

	dlclose(handle);
	fclose(test_file);
	return get_exit_code();
}

#pragma GCC diagnostic pop
#pragma clang diagnostic pop
