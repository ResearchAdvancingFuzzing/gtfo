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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "analysis.h"
#include "analysis_common.h"
#include "common/logger.h"
#include "common/types.h"

// the size of the AFL bitmap
static size_t map_size = 0;
// Regions yet untouched by fuzzing
static u8 *virgin_bits = NULL;
// checksum of the last seen results
static u32 last_checksum = 0;

#define ROL64(_x, _r) ((((u64)(_x)) << (_r)) | (((u64)(_x)) >> (64 - (_r))))

// 64 bit optimized version of AFL's hash function taken from AFL source
static inline u32
afl_hash32(const void *key, u32 len, u32 seed)
{
	const u64 *data = (const u64 *)key;
	u64        h1   = seed ^ len;
	len >>= 3;
	while (len--) {
		u64 k1 = *data++;
		k1 *= 0x87c37b91114253d5ULL;
		k1 = ROL64(k1, 31);
		k1 *= 0x4cf5ad432745937fULL;
		h1 ^= k1;
		h1 = ROL64(h1, 27);
		h1 = h1 * 5 + 0x52dce729;
	}
	h1 ^= h1 >> 33;
	h1 *= 0xff51afd7ed558ccdULL;
	h1 ^= h1 >> 33;
	h1 *= 0xc4ceb9fe1a85ec53ULL;
	h1 ^= h1 >> 33;
	return (u32)h1;
}

// loads a bitmap from a file
static int
load_from_file(char *filename)
{
	if(strlen(filename)) {

		int file_fd = open(filename, O_RDONLY);
		if (file_fd == -1) {
			log_fatal("loading analysis open failed");
		}
		ssize_t read_size = read(file_fd, virgin_bits, map_size);
		if (read_size == -1) {
			log_fatal("loading analysis read failed");
		}
		if (read_size >= 0 && (size_t)read_size != map_size) {
			log_fatal("file wrong size");
		}
		close(file_fd);
	}
	return 0;
}

// save the current bitmap to a file
static void
save_to_file(char *filename)
{
	int file_fd = open(filename, O_WRONLY | O_CREAT, 0600);
	if (file_fd == -1) {
		log_fatal("saving analysis open failed");
	}

	ssize_t write_size = write(file_fd, virgin_bits, map_size);
	if (write_size == -1) {
		log_fatal("saving analysis write failed");
	}
	if (write_size >= 0 && (size_t)write_size != map_size) {
		log_fatal("saving failed");
	}
	close(file_fd);
}

static void
init(char *filename)
{
	init_logging();
	char *env_map_size = getenv("ANALYSIS_SIZE");
	if (env_map_size == NULL) {
		log_fatal("Missing ANALYSIS_SIZE environment variable.");
	}
	size_t size = strtoull(env_map_size, NULL, 0);

	if (size > UINT32_MAX) {
		log_fatal("ANALYSIS_SIZE must be <= uint32 max.");
	}
	map_size    = size;
	virgin_bits = malloc(map_size);
	memset(virgin_bits, 255, map_size);
	if (filename != NULL) {
		load_from_file(filename);
	}
}

static void
destroy()
{
	map_size = 0;
	free(virgin_bits);
}

/*	Comment from AFL source:
		Check if the current execution path brings anything new to the table.
		Update virgin bits to reflect the finds. Returns 1 if the only change is
		the hit-count for a particular tuple; 2 if there are new tuples seen.
		Updates the map, so subsequent calls will always return 0.

		This function is called after every exec() on a fairly large buffer, so
		it needs to be fast. We do this in 32-bit and 64-bit flavors. */
static inline u8
has_new_bits(u8 *trace_bits, u8 *virgin_map)
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
	u64 *current = (u64 *)trace_bits;
	u64 *virgin  = (u64 *)virgin_map;
#pragma clang diagnostic pop
	u32 i = (u32)(map_size >> 3);

	u8 ret = 0;

	while (i--) {
		/* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
		that have not been already cleared from the virgin map - since this will
		almost always be the case. */
		if (unlikely(*current) && unlikely(*current & *virgin)) {

			if (likely(ret < 2)) {

				u8 *cur = (u8 *)current;
				u8 *vir = (u8 *)virgin;

				/* Looks like we have not found any new bytes yet; see if any non-zero
				bytes in current[] are pristine in virgin[]. */
				if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) || (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) || (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) || (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) {
					ret = 2;
				} else {
					ret = 1;
				}
			}
			*virgin &= ~*current;
		}
		current++;
		virgin++;
	}
	return ret;
}

// return value is true if the input was previously seen
static bool
add(u8 *element, size_t element_size)
{
	if (element_size != map_size) {
		log_fatal("illegal element size");
	}
	u8  ret = 0;
	u32 new_checksum;
	//Compute a hash of the bits, and use that to detect a change.  It's faster
	new_checksum = afl_hash32(element, (u32)element_size, 0xAABBCCDD);
	if (last_checksum != new_checksum) {
		ret = has_new_bits(element, virgin_bits);
		if (!last_checksum) {
			last_checksum = new_checksum;
		}
	}
	if (ret == 0) {
		return true;
	}
	if (ret == 1) {
		return false;
	}
	if (ret == 2) {
		return false;
	}
	log_fatal("unknown return value");
}

static void
create_analysis(analysis_api *s)
{
	s->version     = VERSION_ONE;
	s->name        = "AFL bitmap";
	s->description = "This is an implementation of AFL's bitmap logic.";
	s->initialize  = init;
	s->add         = add;
	s->save        = save_to_file;
	s->destroy     = destroy;
	s->merge       = bit_merge;
}

analysis_api_getter get_analysis_api = create_analysis;
