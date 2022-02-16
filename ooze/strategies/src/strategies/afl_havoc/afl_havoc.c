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

#include "afl_havoc.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "afl.h"
#include "afl_config.h"
#include "common/types.h"
#include "mutate.h"
#include "strategy.h"
#include "openssl/md5.h"

#ifdef AFL_HAVOC_IS_MASTER
get_fuzzing_strategy_function get_fuzzing_strategy = afl_havoc_populate;
#endif

static FILE* log_file; 
static unsigned char md5_result[MD5_DIGEST_LENGTH]; 
static bool do_logging = false;

static void write_md5_sum(unsigned char* md, FILE* fp) { 
    int i;
    for (i = 0; i < MD5_DIGEST_LENGTH;  i++) { 
        fprintf(fp, "%02x", md[i]); 
        printf("%02x", md[i]);
    }
    fprintf(fp, "\n"); 
    printf("\n");
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-case-range"
static inline void
afl_havoc_update(strategy_state *state)
{
	//afl_havoc_substates *substates = (afl_havoc_substates *)state->internal_state;
	state->iteration++;
        printf("UPDATING\n");
        //printf("prng state: %lu\n", substates->prng_state->state); 

	//prng_state_update(substates->prng_state);
        //printf("prng state: %lu\n", substates->prng_state->state); 
}

// serialize a state into a string!
static inline char *
afl_havoc_serialize(strategy_state *state)
{
	afl_havoc_substates *substates = (afl_havoc_substates *)state->internal_state;

	char  *s_state      = NULL;
	char  *s_user_dict  = NULL;
	char  *s_auto_dict  = NULL;
	char  *s_prng_state = NULL;
	char  *s_all        = NULL;
	size_t total_len;

	s_state   = strategy_state_serialize(state, "afl_havoc");
	total_len = strlen(s_state);

	s_prng_state = prng_state_serialize(substates->prng_state);
	total_len += strlen(s_prng_state);

	if (substates->user_dict) {
		s_user_dict = dictionary_serialize(substates->user_dict);
		total_len += strlen(s_user_dict);
	}

	if (substates->auto_dict) {
		s_auto_dict = dictionary_serialize(substates->auto_dict);
		total_len += strlen(s_auto_dict);
	}

	s_all = calloc(1, total_len + 1);

	strcat(s_all, s_state);
	strcat(s_all, s_prng_state);

	if (s_user_dict) {
		strcat(s_all, s_user_dict);
	}
	if (s_auto_dict) {
		strcat(s_all, s_auto_dict);
	}

	free(s_state);
	free(s_prng_state);
	free(s_user_dict);
	free(s_auto_dict);

	return s_all;
}

// deserialize an afl_havoc strategy state.
static inline strategy_state *
afl_havoc_deserialize(char *s_state, size_t s_state_size)
{
	afl_havoc_substates *substates = calloc(1, sizeof(afl_havoc_substates));
	strategy_state      *state     = strategy_state_deserialize(s_state, s_state_size);
	char                *serialized_substrategy;

	// prng_state must be present and follow strategy_state.
	serialized_substrategy = strstr(s_state + 1, "\n---") + 1;
	substates->prng_state  = prng_state_deserialize(serialized_substrategy, s_state_size - (size_t)(serialized_substrategy - s_state));

	// if a dictionary follows, it must be the user_dictionary
	serialized_substrategy = strstr(serialized_substrategy + 1, "\n---") + 1;
	if (serialized_substrategy != (void *)1) {

		substates->user_dict = dictionary_deserialize(serialized_substrategy, s_state_size - (size_t)(serialized_substrategy - s_state));

		// if yet another dictionary follows, it must be the auto_dictionary
		serialized_substrategy = strstr(serialized_substrategy + 1, "\n---") + 1;
		if (serialized_substrategy != (void *)1) {

			substates->auto_dict = dictionary_deserialize(serialized_substrategy, s_state_size - (size_t)(serialized_substrategy - s_state));
		}
	}

	state->internal_state = substates;

	return state;
}

// print an afl_havoc strategy state
static inline char *
afl_havoc_print(strategy_state *state)
{
	afl_havoc_substates *substates = (afl_havoc_substates *)state->internal_state;

	char *p_state      = NULL;
	char *p_user_dict  = NULL;
	char *p_auto_dict  = NULL;
	char *p_prng_state = NULL;

	p_state           = strategy_state_print(state, "afl_havoc");
	size_t total_size = strlen(p_state);
	if (substates->user_dict) {
		p_user_dict = dictionary_print(substates->user_dict);
		total_size += strlen(p_user_dict);
	}
	if (substates->auto_dict) {
		p_auto_dict = dictionary_print(substates->auto_dict);
		total_size += strlen(p_auto_dict);
	}
	p_prng_state = prng_state_print(substates->prng_state);
	total_size += strlen(p_prng_state);

	char *p_all = calloc(1, 128 + total_size + 1);

	strcat(p_all, p_state);
	if (p_user_dict) {
		strcat(p_all, "User Dictionary:\n");

		strcat(p_all, p_user_dict);
	}
	if (p_auto_dict) {
		strcat(p_all, "Auto Dictionary:\n");
		strcat(p_all, p_auto_dict);
	}
	strcat(p_all, p_prng_state);

	free(p_state);
	free(p_user_dict);
	free(p_auto_dict);
	free(p_prng_state);

	return p_all;
}

// copy a afl_havoc strategy state.
static inline strategy_state *
afl_havoc_copy(strategy_state *state)
{
	strategy_state      *new_state     = strategy_state_copy(state);
	afl_havoc_substates *substates     = (afl_havoc_substates *)state->internal_state;
	afl_havoc_substates *new_substates = calloc(1, sizeof(afl_havoc_substates));

	if (substates->user_dict) {
		new_substates->user_dict = dictionary_copy(substates->user_dict);
	}
	if (substates->auto_dict) {
		new_substates->auto_dict = dictionary_copy(substates->auto_dict);
	}
	new_substates->prng_state = prng_state_copy(substates->prng_state);

	new_state->internal_state = new_substates;

	return new_state;
}

// free an afl_havoc strategy state.
static inline void
afl_havoc_free(strategy_state *state)
{
    if (do_logging) {
        fclose(log_file); 
    }
	afl_havoc_substates *substates = (afl_havoc_substates *)state->internal_state;

	if (substates->user_dict) {
		dictionary_free(substates->user_dict);
	}
	if (substates->auto_dict) {
		dictionary_free(substates->auto_dict);
	}

	prng_state_free(substates->prng_state);
	free(substates);
	free(state);
}

static inline strategy_state *
afl_havoc_create(u8 *seed, size_t max_size, ...)
{
	strategy_state      *state     = strategy_state_create(seed, max_size);
	afl_havoc_substates *substates = calloc(1, sizeof(afl_havoc_substates));
	// get path to files describing dictionaries to use.
	char *user_dict_file = getenv("USER_DICTIONARY_FILE");
	char *auto_dict_file = getenv("AUTO_DICTIONARY_FILE");

	if (user_dict_file) {
		substates->user_dict = dictionary_load_file(user_dict_file, MAX_USER_DICT_ENTRIES, MAX_USER_DICT_ENTRY_LEN);
	}
	if (auto_dict_file) {
		substates->auto_dict = dictionary_load_file(auto_dict_file, MAX_AUTO_DICT_ENTRIES, MAX_AUTO_DICT_ENTRY_LEN);
	}

	substates->prng_state = prng_state_create((u64)*seed, 0);

	state->internal_state = substates;

        char* env_log_file = getenv("LOG_FILE"); 
        if (env_log_file != NULL) { 
            do_logging = true;
            log_file = fopen(env_log_file, "a"); 
            if (!log_file) 
                log_fatal("Fopen failed"); 
        }

	return state;
}

static inline size_t
afl_havoc(u8 *buf, size_t size, strategy_state *state)
{
	afl_havoc_substates *substates = (afl_havoc_substates *)state->internal_state;
        char* stage_name = "havoc "; 

	// Make a copy of the pseudo-random number generator (prng) state for use within this function.
	// We need prnt_state_UR to return different values with each call here, hence advance its state here.
	// However, our protocol is that its state does not advance for the outside world until the caller invokes afl_havoc_update.
	// Therefore, we use our own private prng_state here, leaving the global prng_state untouched.

	//prng_state *prng_state = prng_state_copy(substates->prng_state);
	prng_state *prng_state = substates->prng_state;
	u32         i;

	static_assert(HAVOC_STACK_POW2 != 0, "HAVOC_STACK_POW2 can't be 0");

	u32 use_stacking = (u8)1 << ((u32)1 + prng_state_UR(prng_state, HAVOC_STACK_POW2));
        printf("use_stacking: %u\n", use_stacking); 

	u64 mutation_limit = 15;
	if (substates->user_dict && substates->user_dict->entry_cnt)
		mutation_limit++;
	if (substates->auto_dict && substates->auto_dict->entry_cnt)
		mutation_limit++;

	for (i = 0; i < use_stacking; i++) {

		// exit if buffer has been obliterated.
		if (!size) {
			break;
		}

		u64 mutation_choice = prng_state_UR(prng_state, mutation_limit);
                printf("switch value: %lu, size: %lu\n", mutation_choice, size);
		switch (mutation_choice) {

		// Flip a single bit somewhere
		case 0: {
			bit_flip(buf, prng_state_UR(prng_state, size << 3));
			break;
		}

		// set byte to a random interesting value
		case 1: {
                        u64 size_interesting_8 = 9; 
                        u8 random_val =  (u8) prng_state_UR(prng_state, size_interesting_8);  
                        u64 random_byte = prng_state_UR(prng_state, size); 
			byte_interesting(buf, random_byte, random_val);

			//byte_interesting(buf, prng_state_UR(prng_state, size), (u8)prng_state_UR(prng_state, 256));
			break;
		}

		// set word to a random interesting value, random endianness
		case 2: {
			if (size < 2) {
				break;
			}
                            u64 size_interesting_16 = 38;

			if (prng_state_UR(prng_state, 2)) {
                        u8 random_val =  (u8) prng_state_UR(prng_state, size_interesting_16 >> 1);  
                        u64 random_byte = prng_state_UR(prng_state, size - 1); 
				//two_byte_interesting_le(buf, (u64)prng_state_UR(prng_state, size - 1), (u8)prng_state_UR(prng_state, 256));
                                two_byte_interesting_le(buf, random_byte, random_val); 
			} else {
                        u8 random_val =  (u8) prng_state_UR(prng_state, size_interesting_16 >> 1);  
                        u64 random_byte = prng_state_UR(prng_state, size - 1); 
				//two_byte_interesting_be(buf, (u64)prng_state_UR(prng_state, size - 1), (u8)prng_state_UR(prng_state, 256));
                                two_byte_interesting_be(buf, random_byte, random_val); 
			}
			break;
		}

		// set dword to a random interesting value, random endianness
		case 3: {

			if (size < 4) {
				break;
			}
                        u64 sizeof_interesting_32 = 108;
			
                        if (prng_state_UR(prng_state, 2)) {
                        u8 random_val =  (u8) prng_state_UR(prng_state, sizeof_interesting_32 >> 2);  
                        u64 random_byte = prng_state_UR(prng_state, size - 3); 
                            four_byte_interesting_le(buf, random_byte, random_val);
				//four_byte_interesting_le(buf, prng_state_UR(prng_state, size - 3), (u8)prng_state_UR(prng_state, 256));
			} else {
                        u8 random_val =  (u8) prng_state_UR(prng_state, sizeof_interesting_32 >> 2);  
                        u64 random_byte = prng_state_UR(prng_state, size - 3); 
                            four_byte_interesting_be(buf, random_byte, random_val);
				//four_byte_interesting_be(buf, prng_state_UR(prng_state, size - 3), (u8)prng_state_UR(prng_state, 256));
			}
			break;
		}
		// random subtract from byte at random position
		case 4: {
                        u8 random_val =  -((u8) 1 + (u8) prng_state_UR(prng_state, MAX_ARITH));  
                        u64 random_byte = prng_state_UR(prng_state, size); 
                        byte_add(buf, random_byte, random_val);
			//byte_add(buf, prng_state_UR(prng_state, size), (u8)(-((s8)prng_state_UR(prng_state, MAX_ARITH))));
			break;
		}
		// random add to byte at random position
		case 5: {

                        u8 random_val = 1 + (u8) prng_state_UR(prng_state, MAX_ARITH); 
                        u64 random_byte = prng_state_UR(prng_state, size); 
			byte_add(buf, random_byte, random_val); 
			break;
		}
		// random subtract from word, random endian
		case 6: {
			if (size < 2) {
				break;
			}

			if (prng_state_UR(prng_state, 2)) {
                        u64 random_byte = prng_state_UR(prng_state, size - 1); 
                        u16 random_val =  (u16)(-(1 + (s16)prng_state_UR(prng_state, MAX_ARITH)));
                            two_byte_add_le(buf, random_byte, random_val); 
				//two_byte_add_le(buf, prng_state_UR(prng_state, size - 1), (u16)(-((s16)prng_state_UR(prng_state, MAX_ARITH))));
			} else {
                        u64 random_byte = prng_state_UR(prng_state, size - 1); 
                        u16 random_val =  (u16)(-(1 + (s16)prng_state_UR(prng_state, MAX_ARITH)));
                            two_byte_add_be(buf, random_byte, random_val);
				//two_byte_add_be(buf, prng_state_UR(prng_state, size - 1), (u16)(-((s16)prng_state_UR(prng_state, MAX_ARITH))));
			}
			break;
		}
		// random add to word, random endian
		case 7: {
                            printf("BEGIN: size: %lu, MAX_ARTIH: %d\n", size, MAX_ARITH); 
			if (size < 2) {
				break;
			}
                            printf("size: %lu, MAX_ARTIH: %d\n", size, MAX_ARITH); 
			if (prng_state_UR(prng_state, 2)) {
                        u64 random_byte = prng_state_UR(prng_state, size - 1); 
                        u16 random_val =  1 + (u16)(prng_state_UR(prng_state, MAX_ARITH));
                            two_byte_add_le(buf, random_byte, random_val); 
			//	two_byte_add_le(buf, prng_state_UR(prng_state, size - 1), (u16)prng_state_UR(prng_state, MAX_ARITH));
			} else {
                        u64 random_byte = prng_state_UR(prng_state, size - 1); 
                        u16 random_val =  1 + (u16)(prng_state_UR(prng_state, MAX_ARITH));
                            two_byte_add_be(buf, random_byte, random_val); 
			//	two_byte_add_be(buf, prng_state_UR(prng_state, size - 1), (u16)prng_state_UR(prng_state, MAX_ARITH));
			}
			break;
		}
		// random subtract from dword, random endian
		case 8: {
			if (size < 4) {
				break;
			}

			if (prng_state_UR(prng_state, 2)) {
                        u64 random_byte = prng_state_UR(prng_state, size - 3); 
                        u32 random_val =   (u32)(-(1 + (s32)prng_state_UR(prng_state, MAX_ARITH)));
                            four_byte_add_le(buf, random_byte, random_val); 
				//four_byte_add_le(buf, prng_state_UR(prng_state, size - 3), (u32)(-((s32)prng_state_UR(prng_state, MAX_ARITH))));
			} else {
                        u64 random_byte = prng_state_UR(prng_state, size - 3); 
                        u32 random_val =  1 + (u32)(-(1 + (s32)prng_state_UR(prng_state, MAX_ARITH)));
                            four_byte_add_be(buf, random_byte, random_val); 
				//four_byte_add_be(buf, prng_state_UR(prng_state, size - 3), (u32)(-((s32)prng_state_UR(prng_state, MAX_ARITH))));
			}
			break;
		}
		// random add to dword, random endian
		case 9: {
			if (size < 4) {
				break;
			}

			if (prng_state_UR(prng_state, 2)) {
                        u64 random_byte = prng_state_UR(prng_state, size - 3); 
                        u32 random_val =  1 + (u32)(prng_state_UR(prng_state, MAX_ARITH));
                            four_byte_add_le(buf, random_byte, random_val); 
				//four_byte_add_le(buf, prng_state_UR(prng_state, size - 3), (u32)prng_state_UR(prng_state, MAX_ARITH));
			} else {
                        u64 random_byte = prng_state_UR(prng_state, size - 3); 
                        u32 random_val =  1 + (u32)(prng_state_UR(prng_state, MAX_ARITH));
                            four_byte_add_be(buf, random_byte, random_val); 
			//	four_byte_add_be(buf, prng_state_UR(prng_state, size - 3), (u32)prng_state_UR(prng_state, MAX_ARITH));
			}
			break;
		}
		// set a random byte to rand value
		case 10: {
                        u8 random_val =  (u8) 1 + (u8) prng_state_UR(prng_state, 255); 
                        u64 random_byte = prng_state_UR(prng_state, size); 
                        random_val = buf[random_byte] ^ random_val; 
			byte_replace(buf, size, random_byte, random_val);
			//byte_replace(buf, size, prng_state_UR(prng_state, size), (u8)1 + (u8)prng_state_UR(prng_state, 255));
			break;
		}
		// delete bytes
		case 11 ... 12: {
			/* Delete bytes. We're making this a bit more likely than insertion (the next option) in hopes of keeping files reasonably small. */

			if (size < 2) {
				break;
			}

			// len in range {0, ... , size-1}
			u64 del_len = afl_choose_block_len(prng_state, size - 1);

			// del_from in range {0, ..., size - del_len}
			u64 del_from = prng_state_UR(prng_state, size - del_len + 1);
                        printf("del_len: %lu, del_from: %lu\n", del_len, del_from);
			n_byte_delete(buf, size, del_from, del_len);

			size -= del_len;
			break;
		}
		// Clone bytes (75%) or insert a block of constant bytes (25%).
		case 13: {
			// check that an insertion will never go over the max buffer size
                        u64 MAX_FILE = 1 * 1024 * 1024; 
                        //printf("size + HAVOC: %lu, max_size: %lu\n", size + HAVOC_BLK_XL, state->max_size);
			if (size + HAVOC_BLK_XL < MAX_FILE) {
			//if (size + HAVOC_BLK_XL < state->max_size) {

				// whether to clone a block of existing bytes or to insert a block of constant bytes
				u8 do_copy = (u8)prng_state_UR(prng_state, 4);

				u64 block_size = 0;
				u64 src_offset = 0;

				if (do_copy) {
					// block size in range {0, ..., size};
					block_size = afl_choose_block_len(prng_state, size);

					// src offset in range {0, ..., size - block_size - 1}
					//if (size - block_size == 0) {
					//	break;
					//}
					src_offset = prng_state_UR(prng_state, size - block_size + 1);
				} else
					block_size = afl_choose_block_len(prng_state, HAVOC_BLK_XL);
				// dest_offset in range {0, ..., size - 1}
				u64 dest_offset = prng_state_UR(prng_state, size);
                                u8* new_buf = calloc(1, size + block_size); 
                                memcpy(new_buf, buf, dest_offset); 
                                printf("size: %lu, src_offset: %lu, dest_offset: %lu, block_size: %lu\n", size, src_offset, dest_offset, block_size);

				if (do_copy) {
                                    printf("CASE1\n"); 
					n_byte_copy_and_ins(new_buf, size, src_offset, dest_offset, block_size);
				} else {
                                    printf("CASE2\n");
					// insert a block of constant bytes at dest_offset
					u8 const_byte = (u8)(prng_state_UR(prng_state, 2) ? prng_state_UR(prng_state, 256) : buf[prng_state_UR(prng_state, size)]);
					memset(new_buf + dest_offset, const_byte, block_size);
				}
                                memcpy(new_buf + dest_offset + block_size, buf + dest_offset, size - dest_offset);
                                free(buf);
                                buf = new_buf;
                                //
                                //n_byte_copy_and_ins(buf, size, dest_offset + block_size, dest_offset, size - src_offset); 
				// update size
				size += block_size;
			}
			break;
		}
		// Overwrite bytes with a randomly selected chunk (75%) or fixed bytes (25%).
		case 14: {

			if (size < 2) {
				break;
			}

			u64 block_size = 0;
			// how many bytes to copy, in range {0, ..., size - 1}
			//if (src_offset > dest_offset) {
				block_size = afl_choose_block_len(prng_state, size - 1); //- src_offset);
			//} else {
			//	block_size = afl_choose_block_len(prng_state, size - 1); //dest_offset);
			//}
			// offset of bytes to copy, anywhere from {0, ..., size - 1};
                        printf("SIZE: %lu\n", size);
			u64 src_offset = prng_state_UR(prng_state, size - block_size + 1);
                        printf("SIZE: %lu\n", size);
			// destination for bytes, anywhere from {0, ..., size - 1}.
			u64 dest_offset = prng_state_UR(prng_state, size - block_size + 1);
                        printf("copy len: %lu, copy_from: %lu, copy_to: %lu\n", block_size, src_offset, dest_offset);

			if (prng_state_UR(prng_state, 4)) {

				if (src_offset != dest_offset) {
					memmove(buf + dest_offset, buf + src_offset, block_size);
				}
			} else {
				memset(buf + dest_offset, (int)(prng_state_UR(prng_state, 2) ? prng_state_UR(prng_state, 256) : buf[prng_state_UR(prng_state, size)]), block_size);
			}
			break;
		}

		// If both user_dict and auto_dict exist, we will always choose user_dict for case 15 and auto_dict for case 16.
		// If only one of the two dictionaries exist, we will never choose case 16 and case 15 will have to determine which to use.
		case 15: {

			dictionary_entry *entry = NULL;

			// Start by assuming the preferred dictionary for case 16, user_dict, exists.
			if (substates->user_dict && substates->user_dict->entry_cnt) {
				// get a token
				entry = (*substates->user_dict->entries)[prng_state_UR(prng_state, substates->user_dict->entry_cnt)];
			}
			// no user dict, so try auto dict if it exists
			else if (substates->auto_dict && substates->auto_dict->entry_cnt) {
				entry = (*substates->auto_dict->entries)[prng_state_UR(prng_state, substates->auto_dict->entry_cnt)];
			}
			// neither dict existed with entries.
			else {
				break;
			}

			// position is somewhere inside of the buffer to be mutated
			u64 pos = prng_state_UR(prng_state, size - entry->len + 1);

			// if token would overflow the buffer
			if (pos + entry->len > state->max_size) {
				break;
			}

			memcpy(buf + pos, entry->token, entry->len);
			break;
		}

		// insert a dictionary token
		// If we choose case 16, both user_dict and auto_dict must exist, so prefer auto_dict for this choice.
		// If we choose case 16, then both user_dict and auto_dict exist, in which case we will always choose auto_dict for case 16 and user_dict for case 15.
		case 16: {
			dictionary_entry *entry = NULL;

			if (substates->auto_dict && substates->auto_dict->entry_cnt) {
				// get token
				entry = (*substates->auto_dict->entries)[prng_state_UR(prng_state, substates->auto_dict->entry_cnt)];
			}
			// dictionary was empty
			else {
				break;
			}

			// if insertion of token would overflow the buffer
			if (size + entry->len > state->max_size) {
				break;
			}

			u64 pos = prng_state_UR(prng_state, state->max_size - entry->len + 1);

			// if token would overflow the buffer
			if (pos + entry->len > state->max_size) {
				break;
			}

			n_byte_ins(buf, size, pos, entry->token, entry->len);
			size += entry->len;
			break;
		}
		}
                printf("out_buf: %s\n", buf); 
                MD5((unsigned char*) buf, size, md5_result);
                write_md5_sum(md5_result, log_file); 
	}
        printf("out_buf: %s hash: ", buf); 
        fwrite(stage_name, sizeof(char), strlen(stage_name), log_file); 
        MD5((unsigned char*) buf, size, md5_result);
        write_md5_sum(md5_result, log_file); 
	//prng_state_free(prng_state);
        //afl_havoc_update(state); 
        printf("before exiting: prng state: %lu\n", substates->prng_state->state); 
	return size;
}

/* populates fuzzing_strategy structure */
void
afl_havoc_populate(fuzzing_strategy *strategy)
{
	strategy->version          = VERSION_ONE;
	strategy->name             = "afl_havoc";
	strategy->create_state     = afl_havoc_create;
	strategy->mutate           = afl_havoc;
	strategy->serialize        = afl_havoc_serialize;
	strategy->deserialize      = afl_havoc_deserialize;
	strategy->print_state      = afl_havoc_print;
	strategy->copy_state       = afl_havoc_copy;
	strategy->free_state       = afl_havoc_free;
	strategy->description      = "";
	strategy->update_state     = afl_havoc_update;
	strategy->is_deterministic = false;
}
#pragma clang diagnostic pop
