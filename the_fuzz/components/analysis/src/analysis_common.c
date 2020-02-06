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

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "analysis_common.h"
#include "common/logger.h"
#include "common/types.h"

static void load(char *, size_t *, u8 **);
static void
load(char *filename, size_t *size, u8 **buffer)
{
	struct stat stat_buffer;
	int         status = stat(filename, &stat_buffer);
	if (status != 0) {
		log_fatal("stat fails on %s", filename);
	}
	*size = (size_t)stat_buffer.st_size;

	*buffer = calloc(*size, 1);

	int file_fd = open(filename, O_RDONLY);
	if (file_fd == -1) {
		log_fatal("loading analysis open failed");
	}
	ssize_t read_size = read(file_fd, *buffer, *size);
	if (read_size == -1) {
		log_fatal("loading analysis read failed");
	}
	if (read_size >= 0 && (size_t)read_size != *size) {
		log_fatal("loading analysis size mismatch");
	}
	close(file_fd);
}

void
bit_merge(char *a, char *b, char *merge)
{
	init_logging();

	u8 *a_buffer     = NULL;
	u8 *b_buffer     = NULL;
	u8 *merge_buffer = NULL;

	size_t a_size;
	size_t b_size;

	load(a, &a_size, &a_buffer);
	load(b, &b_size, &b_buffer);

	if (a_size != b_size) {
		log_fatal("merge files must be the same");
	}

	merge_buffer = calloc(a_size, 1);

	for (size_t i = 0; i < a_size; i++) {
		merge_buffer[i] = a_buffer[i] | b_buffer[i];
	}

	int file_fd = open(merge, O_WRONLY | O_CREAT, 0600);
	if (file_fd == -1) {
		log_fatal("saving merge open failed");
	}
	ssize_t write_size = write(file_fd, merge, a_size);
	if (write_size == -1) {
		log_fatal("saving merge write failed");
	}
	if (write_size >= 0 && (size_t)write_size != a_size) {
		log_fatal("saving merge size mismatch");
	}
	close(file_fd);
}
