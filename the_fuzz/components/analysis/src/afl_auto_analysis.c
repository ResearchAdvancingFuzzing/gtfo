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

#include "ooze.h"
#include "analysis.h"
#include "analysis_common.h"
#include "analysis_auto.h"
#include "common/logger.h"
#include "common/types.h"
#include "common/strategy_state.h"
#include "common/dictionary.h"

// the size of the AFL bitmap
static size_t map_size = 0;
static size_t auto_max_size = 0;
static size_t auto_min_size = 0;
// Regions yet untouched by fuzzing
static u8 *virgin_bits = NULL;
static u8 *a_collect = NULL; 
static u32 a_len = 0;
// checksum of the last seen results
static u32 last_checksum = 0;
static u32 orig_checksum = 0;

static dictionary* extras;
static size_t extras_cnt;
static u8 auto_changed = 0;
static dictionary* a_extras;
static size_t a_extras_cnt; 

static s8 interesting_8[]  = {INTERESTING_8};
static s16 interesting_16[] = {INTERESTING_8, INTERESTING_16};
static s32 interesting_32[] = {INTERESTING_8, INTERESTING_16, INTERESTING_32};

#define ROL64(_x, _r) ((((u64)(_x)) << (_r)) | (((u64)(_x)) >> (64 - (_r))))

// 64 bit optimized version of AFL's hash function taken from AFL source
#pragma clang diagnostic ignored "-Wunreachable-code"
static inline u32
afl_hash32(const void *key, u32 len, u32 seed)
{
	const u64 *data = (const u64 *)key;
	u64        h1   = seed ^ len;
	len >>= 3;


	printf("HASH: len: %u, seed: %u, data: \n", len, seed);
	u32 i; 
	for (i =0; i<len ; i++){
	//	printf("%lu\n", data[i]);
	}

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
	if (strlen(filename)) {

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

static bool valid_size(char* s) { 
	while (*s) {
		if (*s<'0' || *s>'9') return false;
		s++;
	}
	return true;
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

	char *env_auto_max_size = getenv("AUTO_MAX_SIZE");
	char* env_auto_min_size = getenv("AUTO_MIN_SIZE");

	if (!env_auto_max_size || !env_auto_min_size)
		log_fatal("Missing AUTO_MAX_SIZE/AUTO_MIN_SIZE env var.");
	if (!valid_size(env_auto_max_size) || !valid_size(env_auto_min_size))
		log_fatal("Invalid AUTO_MAX_SIZE/AUTO_MIN_SIZE env var.");

	size_t max_size = strtoull(env_auto_max_size, NULL, 0);
	size_t min_size = strtoull(env_auto_min_size, NULL, 0);

	if (max_size > UINT32_MAX) {
		log_fatal("AUTO_MAX_SIZE must be <= uint32 max.");
	}
	if (min_size > UINT32_MAX) { 
		log_fatal("AUTO_MIN_SIZE unsupported.");
	}

	char* user_dict_file = getenv("USER_DICTIONARY_FILE");
	char *auto_dict_file = getenv("AUTO_DICTIONARY_FILE");


	auto_max_size    = max_size;
	auto_min_size 	 = min_size;

	virgin_bits = malloc(map_size);
	memset(virgin_bits, 255, map_size);
	if (filename != NULL) {
		load_from_file(filename);
	}

	a_collect = malloc(auto_max_size);

	extras = dictionary_load_file(user_dict_file, MAX_USER_DICT_ENTRIES, MAX_USER_DICT_ENTRY_LEN); 
	extras_cnt = extras->entry_cnt;

}

static void
destroy()
{
	map_size = 0;
	a_len = 0;
	free(virgin_bits);
	free(a_collect);
}

/*	Comment from AFL source:
                Check if the current execution path brings anything new to the table.
                Update virgin bits to reflect the finds. Returns 1 if the only change is
                the hit-count for a particular tuple; 2 if there are new tuples seen.
                Updates the map, so subsequent calls will always return 0.

                This function is called after every exec() on a fairly large buffer, so
                it needs to be fast. We do this in 32-bit and 64-bit flavors. */
//#pragma clang diagnostic ignored "-Wunused-function"
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
	printf("HAS_NEW_BITS:\n");
	printf("TRACE_BITS: ");
	u32 iter; 
	for (iter =0; iter<i ; iter++){
		//printf("Iter: %u, %hhu\n", iter, trace_bits[iter]);
		//printf("%hhu\n", virgin_map[iter]);
	}
	exit(1);

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
				if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) || 
					(cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) || 
					(cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) || 
					(cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) {
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

static inline u8 
memcmp_nocase(u8* m1, u8* m2, u32 len) {
	while(len--) if (tolower(*(m1++)) ^ tolower(*(m2++))) return 1;
	return 0;
}


static void 
maybe_add_auto(u8* mem, u32 len) { 
	u32 i;

	// Skip runs of identical bytes 
	for (i = 1; i < len; i++) 
		if (mem[0] ^ mem[i]) break;
	
	if (i == len) return;

	// Reject builtin interesting values 
	if (len == 2) { 
		i = sizeof(interesting_16) >> 1;
		while (i--) {
			if (*((u16*)mem) == interesting_16[i] || 
				*((u16*)mem) == SWAP16(interesting_16[i])) return;
		}
	}

	if (len == 4) { 
		i = sizeof(interesting_32) >> 2; 
		while (i--) { 
			if (*((u32*)mem) == interesting_32[i] ||
				*((u32*)mem) == SWAP32(interesting_32[i])) return;
		}
	}

	// Reject anything that matches existing extras. Do a case-insensitive match

	dictionary_entry** entries = *extras->entries; 
	for (i = 0; i < extras_cnt; i++)
		if (entries[i]->len) break;
	
	for (; i < extras_cnt && entries[i]->len == len; i++) {
		if (!memcmp_nocase(entries[i]->token, mem, len)) return;
	}

	// Last, check a_extras[] for matches 

	auto_changed = 1;
	dictionary_entry** a_entries = *a_extras->entries;
	for (i = 0; i < a_extras_cnt; i++) { 
		if (a_entries[i]->len == len && !memcmp_nocase(a_entries[i]->token, mem, len)) {
			a_entries[i]->hit_cnt++;
			goto sort_a_extras; 
		}
	}

	// We have a new entry. Let's append it if we have room. 

	if (a_extras_cnt < auto_max_size) {
		


	}

	sort_a_extras:
		//qsort(a_entries, a_extras_cnt, sizeof(struct dictionary_entry), )	

	}


// return value is true if the input was previously seen
// need to add the orig_buffer, the orig_size, and the pos to arguments
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wunreachable-code"
static bool
add(u8 *element, size_t element_size, strategy_state* state)
{
	printf("Adding\n");
	printf("iteration: %lu, len: %zu\n", state->iteration, state->size);
    //optional_args* args; 
	if (element_size != map_size) {
		log_fatal("illegal element size");
	}

	u8  ret = 0;
	u32 new_checksum;
	// Compute a hash of the bits, and use that to detect a change.  It's faster
	new_checksum = afl_hash32(element, (u32)element_size, 0xa5b35705);
	printf("new_checksum: %u\n", new_checksum);
	u64 stage_cur_byte = state->iteration;
	u64 stage_cur = state->iteration << 3; 
	u64 stage_max = state->size << 3; // max stage in bits

	// the orig checksum is just the first thing we run, so iteration should be 0
	if (stage_cur_byte == 0) {
		orig_checksum = new_checksum; 
	}

	if ((stage_cur & 7) == 7) {
		if (stage_cur == stage_max - 1 && new_checksum == last_checksum) // EOF 
		{
			if (a_len < auto_max_size) {
				a_collect[a_len] = state->orig_buff[stage_cur_byte];
			}
			a_len++;  
			if (a_len >= auto_min_size && a_len <= auto_max_size) { 
				maybe_add_auto(a_collect, a_len);  
			}
		} else if (new_checksum != last_checksum) { // if checksum has changed, let's check if we have something
			if (a_len >= auto_min_size && a_len <= auto_max_size) {
				maybe_add_auto(a_collect, a_len); 
			}
			a_len = 0;
			last_checksum = new_checksum; 
		}

		if (new_checksum != orig_checksum) {
			if (a_len < auto_max_size) a_collect[a_len] = state->orig_buff[stage_cur_byte];
			a_len++; 
		}
	}


	
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
	s->name        = "AFL autos";
	s->description = "This is an implementation of AFL's auto logic.";
	s->initialize  = init;
	s->add         = add;
	s->save        = save_to_file;
	s->destroy     = destroy;
	s->merge       = bit_merge;
}

analysis_api_getter get_analysis_api = create_analysis;
