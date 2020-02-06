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
#include <unistd.h>

#include "analysis.h"
#include "common/logger.h"
#include "common/types.h"

static u64 current_count = 0;

static int
load_from_file(char *filename)
{
	log_debug("Loading from %s", filename);
	int file_fd = open(filename, O_RDONLY);
	if (file_fd == -1) {
		log_fatal("loading analysis open failed");
	}
	u64     temp;
	ssize_t read_size = read(file_fd, &temp, sizeof(u64));
	if (read_size == -1) {
		log_fatal("loading analysis read failed");
	}
	current_count = temp;
	close(file_fd);
	return 0;
}

static void
save_to_file(char *filename)
{
	int file_fd = open(filename, O_WRONLY | O_CREAT, 0600);
	if (file_fd == -1) {
		log_fatal("saving analysis open failed");
	}

	ssize_t write_size = write(file_fd, &current_count, sizeof(u64));
	if (write_size == -1) {
		log_fatal("saving analysis write failed");
	}
	close(file_fd);
}

static void
merge(char *a, char *b, char *merge)
{
	init_logging();
	int     file_fd    = -1;
	ssize_t read_size  = -1;
	ssize_t write_size = -1;
	log_debug("Loading from %s", a);
	file_fd = open(a, O_RDONLY);
	if (file_fd == -1) {
		log_fatal("loading analysis open failed");
	}
	u64 a_value;
	read_size = read(file_fd, &a_value, sizeof(u64));
	if (read_size == -1) {
		log_fatal("loading analysis read failed");
	}

	log_debug("Loading from %s", b);
	file_fd = open(b, O_RDONLY);
	if (file_fd == -1) {
		log_fatal("loading analysis open failed");
	}
	u64 b_value;
	read_size = read(file_fd, &b_value, sizeof(u64));
	if (read_size == -1) {
		log_fatal("loading analysis read failed");
	}

	u64 merged = a_value > b_value ? a_value : b_value;

	file_fd = open(merge, O_WRONLY | O_CREAT, 0600);
	if (file_fd == -1) {
		log_fatal("saving analysis open failed");
	}

	write_size = write(file_fd, &merged, sizeof(u64));
	if (write_size == -1) {
		log_fatal("saving analysis write failed");
	}
	close(file_fd);
}

static void
init(char *filename)
{
	init_logging();

	char *env_size = getenv("ANALYSIS_SIZE");
	if (env_size == NULL) {
		log_fatal("Missing ANALYSIS_SIZE environment variable.");
	}
	size_t size = strtoull(env_size, NULL, 0);
	if (size == 0) {
		log_fatal("ANALYSIS_SIZE invalid");
	}

	if (size != sizeof(u64)) {
		log_fatal("ANALYSIS_SIZE must be %d", sizeof(u64));
	}
	if (filename != NULL) {
		load_from_file(filename);
	}
}

static void
destroy()
{
	current_count = 0;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
static bool
add(u8 *element, size_t element_size)
{
	if (element_size != sizeof(u64)) {
		log_fatal("this analysis only accepts 64 bit integers");
	}

	u64 *eptr = (u64 *)element;
	if (*eptr > current_count) {
		current_count = *eptr;
		return 0;
	}
	return 1;
}
#pragma clang diagnostic pop

static void
create_analysis(analysis_api *s)
{
	s->version     = VERSION_ONE;
	s->name        = "KVM Demo Analysis";
	s->description = "This is for use with the SAGE test and the KVM jig test.";
	s->initialize  = init;
	s->add         = add;
	s->save        = save_to_file;
	s->destroy     = destroy;
	s->merge       = merge;
}

analysis_api_getter get_analysis_api = create_analysis;
