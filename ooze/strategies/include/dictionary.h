#ifndef DICTIONARY_H
#define DICTIONARY_H

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
#include <bits/stdint-uintn.h>
#include <stddef.h>

#include "afl_config.h"
#include "common/types.h"
#include "mutate.h"
#include "strategy.h"

/*
    Methods for manipulating dictionary and dictionary_entry objects.

    Dictionaries are used to hold fixed bytestrings that
    are commonly used by the program being fuzzed.

    The entries are sorted by token length, smallest first.
*/

// defined in afl_config.h
#ifndef MAX_LINE
#define MAX_LINE 8192
#endif

// an entry in a dictionary. Describes and contains a token string.
typedef struct dictionary_entry {
	// length of the token string
	size_t len;
	// idk, taken from afl, might use later
	size_t hit_cnt;
	u8    *token;
} dictionary_entry;

typedef struct dictionary {

	// number of entries that this dictionary contains
	size_t entry_cnt;

	// maximum number of entries allowed
	size_t max_entry_cnt;

	// maximum string length of tokens in this dictionary
	size_t max_token_len;

	// pointer to array of pointers, with each pointing to a dictionary entry
	struct dictionary_entry *(*entries)[];
} dictionary;

char *dictionary_entry_print(dictionary_entry *entry);

dictionary_entry *dictionary_entry_create(u8 *token);
void              dictionary_entry_free(dictionary_entry *entry);
dictionary_entry *dictionary_entry_copy(dictionary_entry *entry);

char             *dictionary_entry_serialize(dictionary_entry *entry);
dictionary_entry *dictionary_entry_deserialize(char *s_entry);

int         compare_entries(const void *p, const void *q);
char       *dictionary_print(dictionary *dict);
dictionary *dictionary_create(size_t max_entry_cnt, size_t max_token_len);
void        dictionary_free(dictionary *dict);
uint8_t     dictionary_add_entry(dictionary *dict, dictionary_entry *new_entry);

dictionary *dictionary_copy(dictionary *dict);
dictionary *dictionary_merge(dictionary *a, dictionary *b);
dictionary *dictionary_load_file(char *filename, size_t max_entries, size_t max_token_len);

char       *dictionary_serialize(dictionary *dict);
dictionary *dictionary_deserialize(char *s_dict, size_t s_dict_size);

#endif
