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

#include "tap.h"
#include <stdio.h>
#include <stdlib.h>

// see http://testanything.org/tap-version-13-specification.html for more info

unsigned long current_test;
unsigned long plan_count;
int           exit_code = 0;

static void
increment_test_and_check()
{
	int retval = 0;
	current_test++;
	if (current_test > plan_count) {
		char *desc;
		retval = asprintf(&desc, "Expected %lu tests, but tried to run %lu.", plan_count, current_test);
		if (retval < 0) {
			fprintf(stderr, "asprintf failed near line %d\n", __LINE__);
		}
		bail_out(desc);
	}
}

void
print_tap_header(void)
{
	printf("TAP version 13\n");
}

// records the number of tests to be performed
void
plan(unsigned long tests)
{
	printf("1..%lu\n", tests);
	plan_count = tests;
}

// This function records that a test has been passed
void
ok(bool ok, const char *description)
{
	increment_test_and_check();

	if (ok) {
		printf("ok %lu", current_test);
	} else {
		exit_code = EXIT_FAILURE;
		printf("not ok %lu", current_test);
	}
	if (description != NULL) {
		printf(" - %s", description);
	}
	printf("\n");
}

void
skip(const char *description)
{
	increment_test_and_check();
	printf("ok %lu - # SKIP %s\n", current_test, description);
}

void
todo(const char *description)
{
	increment_test_and_check();
	printf("ok %lu - # TODO %s\n", current_test, description);
}

void
diagnostics(const char *description)
{
	size_t i = 0;
	printf("# ");
	while (description[i] != '\0') {
		putchar(description[i]);
		if (description[i] == '\n') {
			printf("# ");
		}
		i++;
	}
	printf("\n");
}

__attribute__((noreturn)) void
bail_out(const char *description)
{
	printf("Bail out!");
	if (description != NULL) {
		printf(" %s", description);
	}
	printf("\n");
	exit(EXIT_FAILURE);
}

int
get_exit_code()
{
	return exit_code;
}
