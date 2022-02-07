#ifndef TESTFILE_H
#define TESTFILE_H

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
#include <stdio.h>
#define FILE_VERSION_ONE_MAGIC "VERSION 1"

char *
get_line_from_test_file(FILE *test_file);

int
get_test_version(char *version_line);

void
set_envs(char *env_line);

u64
count_tests(FILE *test_file, u8 lines_per_test);

void
check_header(FILE *test_file, char **meta);

void
read_file(size_t max_size, char *filename, size_t *size, u8 **buffer);

char *
get_io_file(char *test_filename, char *filename);

char *
testfile_dir(char *test_filename);

#endif
