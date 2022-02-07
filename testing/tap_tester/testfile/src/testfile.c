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
#include "testfile.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux__
#include <libgen.h>
#include <linux/limits.h>
#endif

// get the directory that the given testfile is in
char *
testfile_dir(char *test_filename)
{
	char  actualpath[PATH_MAX + 1];
	char *rpath = realpath(test_filename, actualpath);
	if (rpath != actualpath) {
		bail_out("realpath failed");
	}
	char *dir = dirname(actualpath);
	return dir;
}

// gets the full path of an io file from the testfile
char *
get_io_file(char *test_filename, char *filename)
{
	char *dir          = testfile_dir(test_filename);
	char *io_file      = NULL;
	int   io_file_size = asprintf(&io_file, "%s/io/%s", dir, filename);
	if (io_file_size < 0) {
		bail_out("asprintf() failed");
	}
	return io_file;
}

/*
    This function reads a line from the test file.
    It returns a pointer to the first character of a line that is not a space.
    Commented lines (lines that begin with a '#') are skipped.
*/
char *
get_line_from_test_file(FILE *file)
{
	char   *line   = NULL;
	char   *result = NULL;
	ssize_t length;
	size_t  n = 0;
	ssize_t i = 0;

	while ((length = getline(&line, &n, file)) != -1) {
		if (line[0] == '#' || line[0] == '\n') {
			continue;
		}

		if (line[length - 1] == '\n') {
			// delete trailing newline
			line[length - 1] = 0;
		}

		i = 0;
		// skip over spaces
		for (; i < length; i++) {
			if (!isspace(line[i])) {
				break;
			}
		}
		result = calloc(1, strlen(line + i) + 1);
		strcpy(result, line + i);
		free(line);
		return result;
	}
	// fail case
	free(line);
	return NULL;
}

// return the version of the testfile
int
get_test_version(char *version_line)
{
	if (version_line) {
		return (strncmp(version_line, FILE_VERSION_ONE_MAGIC, strlen(FILE_VERSION_ONE_MAGIC)) == 0);
	}
	bail_out("Error getting test version.");
	return -1;
}

/*
    Checks that all environment vars that are required by the test are present.
*/
#define STATE_FIND_BEGIN 0
#define STATE_FIND_END 1
#define STATE_FIND_END_QUOTE 2
#define ENV_TAG "ENVS"

// internal helper function used when setting environment variables
static void
parse_env_token(char *token)
{
	static bool env_found = false;
	if (strncmp(token, ENV_TAG, strlen(ENV_TAG)) == 0) {
		env_found = true;
		return;
	}

	if (!env_found) {
		bail_out("Can't find environment variable tag");
	}

	char *var = NULL;
	char *val = NULL;
	var       = strsep(&token, "=");
	if (var == NULL) {
		bail_out("no variable found");
	}
	val = strsep(&token, "=");
	if (val == NULL) {
		bail_out("no value found");
	}

	else if (val[0] == '\"') {
		val++;
	}

	if (*(val + strlen(val)) == '\"') {
		*(val + strlen(val)) = '\0';
	}

	setenv(var, val, 1);
}

// takes the ENVS line from the testfile and sets all of the environment variables
void
set_envs(char *env_line)
{
	char *begin = env_line;
	char *end   = env_line + strlen(env_line);

	char *curr_begin = begin;
	char *curr_end   = begin;

	u8 state = STATE_FIND_BEGIN;
	while (curr_end < end && curr_begin < end) {
		if (isspace((int)*curr_begin)) {
			if (state == STATE_FIND_BEGIN) {
				curr_begin++;
				continue;
			}
			bail_out("ENV parse: invalid state");
		} else if (state == STATE_FIND_BEGIN) {
			state    = STATE_FIND_END;
			curr_end = curr_begin;
			curr_end++;
			continue;
		}

		if (isspace((int)*curr_end)) {
			switch (state) {

			case STATE_FIND_END:
				*curr_end = '\0';
				parse_env_token(curr_begin);
				curr_end++;
				curr_begin = curr_end;
				state      = STATE_FIND_BEGIN;
				continue;

			case STATE_FIND_END_QUOTE:
				curr_end++;
				continue;
			}
		}

		if (*curr_end == '\"') {
			switch (state) {
			case STATE_FIND_END:
				state = STATE_FIND_END_QUOTE;
				curr_end++;
				continue;

			case STATE_FIND_END_QUOTE:
				curr_end++;
				if (isspace((int)*curr_end) || *curr_end == '\0') {
					*curr_end = '\0';
				} else {
					bail_out("ENV parse: invalid state");
				}
				parse_env_token(curr_begin);
				curr_end++;
				curr_begin = curr_end;
				continue;
			}
		}

		if (curr_end == (end - 1)) {
			parse_env_token(curr_begin);
		}
		curr_end++;
	}
}
/*
    This function counts the number of tests that we need to run.
*/
u64
count_tests(FILE *test_file, u8 lines_per_test)
{
	char  *line       = NULL;
	size_t line_count = 0;

	// Count the number of lines
	while ((line = get_line_from_test_file(test_file)) != NULL) {
		free(line);
		line_count++;
	}
	rewind(test_file);
	if ((line_count - 3) % lines_per_test != 0) {
		bail_out("Test file has the wrong number of lines.");
	}

	return ((line_count - 3) / lines_per_test);
}

// handles checking all of the header fields
void
check_header(FILE *test_file, char **meta)
{
	char *magic_line = get_line_from_test_file(test_file);
	if (!magic_line) {
		bail_out("Could not get the first line (VERSION) of the test file.");
	}

	// check that the first line of the test file matches the test version.
	ok(get_test_version(magic_line) == true, "VERSION is set correctly in the test file.");
	free(magic_line);

	// get the environment line.
	char *env_line = get_line_from_test_file(test_file);
	if (!env_line) {
		bail_out("Could not get the second line (ENV) of the test file!");
	}

	set_envs(env_line);
	free(env_line);
	*meta = get_line_from_test_file(test_file);
	if (!(*meta)) {
		bail_out("Could not get the third line (meta) of the test file!");
	}
}

// helper that reads a file into a buffer
void
read_file(size_t max_size, char *filename, size_t *size, u8 **buffer)
{
	// Open the file
	FILE *file = fopen(filename, "r");

	// If we couldn't open the  file
	if (!file) {
		char *desc      = NULL;
		int   desc_size = asprintf(&desc, "Can not open the input file (%s)", filename);
		if (desc_size < 0) {
			fprintf(stderr, "asprintf failed near line %d\n", __LINE__);
		}
		bail_out(desc);
	}

	// get the size of the file
	fseek(file, 0, SEEK_END);
	long file_size = ftell(file);
	if (file_size < 0) {
		bail_out("ftell fail in function read_file in file testfile.c");
	}

	rewind(file);

	size_t buffer_size = 0;

	if (max_size != 0) {
		if ((size_t)file_size > max_size) {

			char *desc = NULL;
			asprintf(&desc, "size of file %s is greater than max size.", filename);
			bail_out(desc);
		}
		buffer_size = max_size;
	} else {
		buffer_size = (size_t)file_size;
	}

	// We allocate one extra byte than the size we report to insure it is null-terminated.
	// This will cover someone performing a strlen() on the buffer.
	*buffer                  = calloc(1, buffer_size + 1);
	size_t read_size         = fread(*buffer, 1, (size_t)(file_size), file);
	*(*buffer + buffer_size) = 0;
	if (read_size != (size_t)file_size) {
		char *desc      = NULL;
		int   desc_size = asprintf(&desc, "read fail(%ld): %s", read_size, strerror(errno));
		if (desc_size < 0) {
			fprintf(stderr, "something has gone terribly wrong\n");
		}
		bail_out(desc);
		free(desc);
	}
	fclose(file);
	*size = (size_t)file_size;
}
