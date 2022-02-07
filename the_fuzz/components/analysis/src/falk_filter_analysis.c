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

#include <bits/stdint-uintn.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "analysis.h"
#include "analysis_common.h"
#include "common/logger.h"
#include "common/types.h"

static u8    *analysis_buffer;
static size_t analysis_buffer_size;

// this should be replaces with a Bloom filter / Quotient filter
#include <x86intrin.h>

/* falkhash() taken from https://github.com/gamozolabs/falkhash
 *
 * Summary:
 *
 * Performs a falkhash and returns the result.
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
static __m128i
falkhash(void *pbuf, uint64_t len, uint64_t pseed)
{
	uint8_t *buf = (uint8_t *)pbuf;

	uint64_t iv[2];

	__m128i hash, seed;

	/* Create the 128-bit seed. Low 64-bits gets seed, high 64-bits gets
	 * seed + len + 1. The +1 ensures that both 64-bits values will never be
	 * the same (with the exception of a length of -1. If you have that much
	 * ram, send me some).
	 */
	iv[0] = pseed;
	iv[1] = pseed + len + 1;

	/* Load the IV into a __m128i */
	seed = _mm_loadu_si128((__m128i *)iv);

	/* Hash starts out with the seed */
	hash = seed;

	while (len) {
		uint8_t tmp[0x50];

		__m128i piece[5];

		/* If the data is smaller than one chunk, pad it with zeros */
		if (len < 0x50) {
			memset(tmp, 0, 0x50);
			memcpy(tmp, buf, len);
			buf = tmp;
			len = 0x50;
		}

		/* Load up the data into __m128is */
		piece[0] = _mm_loadu_si128((__m128i *)(buf + 0 * 0x10));
		piece[1] = _mm_loadu_si128((__m128i *)(buf + 1 * 0x10));
		piece[2] = _mm_loadu_si128((__m128i *)(buf + 2 * 0x10));
		piece[3] = _mm_loadu_si128((__m128i *)(buf + 3 * 0x10));
		piece[4] = _mm_loadu_si128((__m128i *)(buf + 4 * 0x10));

		/* xor each piece against the seed */
		piece[0] = _mm_xor_si128(piece[0], seed);
		piece[1] = _mm_xor_si128(piece[1], seed);
		piece[2] = _mm_xor_si128(piece[2], seed);
		piece[3] = _mm_xor_si128(piece[3], seed);
		piece[4] = _mm_xor_si128(piece[4], seed);

		/* aesenc all into piece[0] */
		piece[0] = _mm_aesenc_si128(piece[0], piece[1]);
		piece[0] = _mm_aesenc_si128(piece[0], piece[2]);
		piece[0] = _mm_aesenc_si128(piece[0], piece[3]);
		piece[0] = _mm_aesenc_si128(piece[0], piece[4]);

		/* Finalize piece[0] by aesencing against seed */
		piece[0] = _mm_aesenc_si128(piece[0], seed);

		/* aesenc the piece into the hash */
		hash = _mm_aesenc_si128(hash, piece[0]);

		buf += 0x50;
		len -= 0x50;
	}

	/* Finalize hash by aesencing against seed four times */
	hash = _mm_aesenc_si128(hash, seed);
	hash = _mm_aesenc_si128(hash, seed);
	hash = _mm_aesenc_si128(hash, seed);
	hash = _mm_aesenc_si128(hash, seed);

	return hash;
}

// UNUSED FUNCTION
/*
static __m128i
hash_func128(void *to_hash, size_t size)
{
        volatile __m128i hash;
        hash = falkhash(to_hash, size, 0x1337133713371337ULL);
        return hash;
}
*/
static u64
hash_func64(void *to_hash, size_t size)
{
	volatile __m128i hash;
	hash = falkhash(to_hash, size, 0x1337133713371337ULL);
	u64 half[2];
	_mm_storeu_si128((__m128i *)half, hash);
	return half[0] ^ half[1];
}

static int
analysis_contains(void *element, size_t element_size)
{
	u64    sum = hash_func64(element, element_size);
	size_t bit = sum % (analysis_buffer_size * 8);
	return (analysis_buffer[bit / 8]) & (u8)(1 << (bit % 8));
}

static void
add_to_analysis(void *element, size_t element_size)
{
	u64    sum = hash_func64(element, element_size);
	size_t bit = sum % (analysis_buffer_size * 8);
	analysis_buffer[bit / 8] |= (u8)(1 << (bit % 8));
}

static bool
check_add_to_analysis(u8 *element, size_t element_size)
{
	if (analysis_contains((void *)element, element_size)) {
		return 1;
	}
	add_to_analysis((void *)element, element_size);
	return 0;
}

static int
load_from_file(char *filename)
{
	log_debug("Loading from %s", filename);
	int file_fd = open(filename, O_RDONLY);
	if (file_fd == -1) {
		log_fatal("loading analysis open failed");
	}
	ssize_t read_size = read(file_fd, analysis_buffer, analysis_buffer_size);
	if (read_size == -1) {
		log_fatal("loading analysis read failed");
	}
	if (read_size >= 0 && (size_t)read_size != analysis_buffer_size) {
		log_fatal("loading analysis size mismatch");
	}
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
	ssize_t write_size = write(file_fd, analysis_buffer, analysis_buffer_size);
	if (write_size == -1) {
		log_fatal("saving analysis write failed");
	}
	if (write_size >= 0 && (size_t)write_size != analysis_buffer_size) {
		log_fatal("saving analysis size mismatch");
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

	analysis_buffer      = (u8 *)calloc(1, size);
	analysis_buffer_size = size;
	if (filename != NULL) {
		load_from_file(filename);
	}
}

static void
destroy()
{
	free(analysis_buffer);
	analysis_buffer      = NULL;
	analysis_buffer_size = 0;
}

static void
create_analysis(analysis_api *s)
{
	s->version     = VERSION_ONE;
	s->name        = "we should come up with a name for this";
	s->description = "This is some weird bloom filter like thing";
	s->initialize  = init;
	s->add         = check_add_to_analysis;
	s->save        = save_to_file;
	s->destroy     = destroy;
	s->merge       = bit_merge;
}

analysis_api_getter      get_analysis_api = create_analysis;
#pragma clang diagnostic pop
