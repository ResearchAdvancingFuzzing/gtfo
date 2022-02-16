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

#include "common/yaml_helper.h"
#include "dictionary.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-case-range"

// Dictionary entry deserialize helper function:
#define SERIALIZE_DICTIONARY_ENTRY(HELPER, ENTRY)                               \
	do {                                                                        \
		YAML_SERIALIZE_START_MAPPING(HELPER);                                   \
		YAML_SERIALIZE_64HEX_PSTRUCT(HELPER, ENTRY, len);                       \
		YAML_SERIALIZE_64HEX_PSTRUCT(HELPER, ENTRY, hit_cnt);                   \
		YAML_SERIALIZE_8HEX_ARRAY(HELPER, (ENTRY)->token, token, (ENTRY)->len); \
		YAML_SERIALIZE_END_MAPPING(HELPER);                                     \
	} while (0);

/*
This file contains methods used for the dictionary and dictionary_entry
objects.
*/

// Create a human-readable string that describes a dictionary_entry object.
inline char *
dictionary_entry_print(dictionary_entry *entry)
{

	size_t total_len = 0;
	char  *p_token   = NULL;
	char  *p_len     = NULL;
	char  *p_hit_cnt = NULL;
	char  *result    = NULL;
	int    retval    = 0;
	// print fields.
	retval = asprintf(&p_token, "token: '%.*s'\n", (int)entry->len, entry->token);
	if (retval < 0) {
		fprintf(stderr, "asprintf failed near line %d\n", __LINE__);
	}

	retval = asprintf(&p_len, "token length: %zu\n", entry->len);
	if (retval < 0) {
		fprintf(stderr, "asprintf failed near line %d\n", __LINE__);
	}

	retval = asprintf(&p_hit_cnt, "token hit count: %zu\n", entry->hit_cnt);
	if (retval < 0) {
		fprintf(stderr, "asprintf failed near line %d\n", __LINE__);
	}

	// figure out total length
	total_len = strlen(p_token) + strlen(p_len) + strlen(p_hit_cnt);

	// alloc buffer to hold all strings + \n + \0
	result = calloc(1, total_len + 2);

	// concat all strings into result buf
	strcat(result, p_token);
	strcat(result, p_len);
	strcat(result, p_hit_cnt);
	strcat(result, "\n");

	// free old chunks
	free(p_token);
	free(p_len);
	free(p_hit_cnt);

	return result;
}

// This function creates a fresh dictionary_entry.
// Note that tokens do not contain a trailing null because they may be non-character data.
inline dictionary_entry *
dictionary_entry_create(u8 *token)
{
	// This strlen() assumes a null-terminated string is supplied. Could be problematic for non-string tokens.
	size_t token_len  = strlen((char *)token);
	u8    *token_copy = calloc(1, token_len);
	// make a copy of the token
	memcpy(token_copy, token, token_len);

	dictionary_entry *new_entry = calloc(1, sizeof(dictionary_entry));

	new_entry->token   = token_copy;
	new_entry->len     = token_len;
	new_entry->hit_cnt = 0;

	return new_entry;
}

// this function frees a dictionary_entry.
inline void
dictionary_entry_free(dictionary_entry *entry)
{
	free(entry->token);
	free(entry);
}

// this function copies a dictionary entry
inline dictionary_entry *
dictionary_entry_copy(dictionary_entry *entry)
{
	dictionary_entry *new_entry = calloc(1, sizeof(dictionary_entry));
	new_entry->token            = calloc(1, entry->len);
	memcpy(new_entry->token, entry->token, entry->len);
	new_entry->len     = entry->len;
	new_entry->hit_cnt = entry->hit_cnt;
	return new_entry;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
// This function is used for qsort, it compares two dictionary_entries.
// We sort based on length, not on value, so that if we are sequentially stepping through
// dictionary entries, we will never insert a shorter value where a longer value was previously
// inserted into the data-under-test. Inserting a shorter value would require restoring some
// trailing original bytes that we no longer possess.
inline int
compare_entries(const void *p, const void *q)
{
	dictionary_entry *foo = *(dictionary_entry **)p;
	dictionary_entry *bar = *(dictionary_entry **)q;

	if (foo->len < bar->len) {
		return -1;
	}
	if (foo->len > bar->len) {
		return 1;
	}
	return 0;
}
#pragma clang diagnostic pop

// This function creates a human-readable string that describes a dictionary
// object.
inline char *
dictionary_print(dictionary *dict)
{
	int    retval          = 0;
	char  *p_entry_cnt     = NULL;
	char  *p_max_entry_cnt = NULL;
	char  *p_max_token_len = NULL;
	char **p_entries       = calloc(1, sizeof(char *) * (dict->entry_cnt));
	char  *p_dict          = NULL;
	size_t total_size      = 0;

	// format these fields
	retval = asprintf(&p_entry_cnt, "Dictionary:\n\tEntry Count: %zu\n", dict->entry_cnt);
	if (retval < 0) {
		fprintf(stderr, "asprintf failed near line %d\n", __LINE__);
	}

	retval = asprintf(&p_max_entry_cnt, "\tMax Entry Count: %zu\n", dict->max_entry_cnt);
	if (retval < 0) {
		fprintf(stderr, "asprintf failed near line %d\n", __LINE__);
	}

	retval = asprintf(&p_max_token_len, "\tMax Token Length: %zu\n\tEntries:\n\n", dict->max_token_len);
	if (retval < 0) {
		fprintf(stderr, "asprintf failed near line %d\n", __LINE__);
	}

	// calc total size thus far
	total_size += strlen(p_entry_cnt) + strlen(p_max_entry_cnt) + strlen(p_max_token_len);

	// get printable versions of each entry
	size_t i = 0;
	for (; i < dict->entry_cnt; i++) {
		p_entries[i] = dictionary_entry_print((*dict->entries)[i]);
		total_size += strlen(p_entries[i]);
	}

	// +1 for newline at end, +1 to guarantee null terminator.
	p_dict = calloc(1, total_size + 2);

	// move data over
	strcat(p_dict, p_entry_cnt);
	strcat(p_dict, p_max_entry_cnt);
	strcat(p_dict, p_max_token_len);

	// move each printed entry to the p_dict object
	// free printed entries as we go.
	i = 0;
	for (; i < dict->entry_cnt; i++) {
		strcat(p_dict, p_entries[i]);
		free(p_entries[i]);
	}
	// add a newline
	strcat(p_dict, "\n");

	// free stuff we no longer need
	free(p_entry_cnt);
	free(p_max_entry_cnt);
	free(p_max_token_len);
	free(p_entries);

	return p_dict;
}

// this function creates a new dictionary.
inline dictionary *
dictionary_create(size_t max_entry_cnt, size_t max_token_len)
{

	dictionary *dict = calloc(1, sizeof(dictionary));

	// alloc space for all dictionary_entry pointers at once
	dictionary_entry *(*entries)[] = calloc(1, sizeof(dictionary_entry *) * max_entry_cnt);

	dict->max_entry_cnt = max_entry_cnt;
	dict->max_token_len = max_token_len;
	dict->entries       = entries;
	return dict;
}

// this function frees a dictionary.
inline void
dictionary_free(dictionary *dict)
{
	// skip null ptrs
	if (dict) {
		size_t i = 0;
		// free each entry in the dictionary
		for (; i < dict->entry_cnt; i++) {
			dictionary_entry_free((*dict->entries)[i]);
		}
		// free the entries table
		free(dict->entries);
		// free the dictionary
		free(dict);
	}
}

// this function adds a new entry to a dictionary.
inline uint8_t
dictionary_add_entry(dictionary *dict, dictionary_entry *new_entry)
{
	// only add entry to dictionary if the dictionary can hold more entries
	// and if the entry's token is sufficiently small.
	if (dict->entry_cnt < dict->max_entry_cnt && new_entry->len <= dict->max_token_len) {
		// add new entry
		(*dict->entries)[dict->entry_cnt] = new_entry;
		// update linked list size
		dict->entry_cnt++;
		// maybe not the best place to do our sorting?
		qsort(dict->entries, dict->entry_cnt, sizeof(dictionary_entry *), &compare_entries);
		return 1;
	}
	return 0;
}

// this function creates a copy of a dictionary and returns a pointer to it.
inline dictionary *
dictionary_copy(dictionary *dict)
{
	size_t i = 0;
	// create a new dict
	dictionary *copy_dict = dictionary_create(dict->max_entry_cnt, dict->max_token_len);

	for (; i < dict->entry_cnt; i++) {
		// copy each entry
		dictionary_entry *copy_entry = dictionary_entry_copy((*dict->entries)[i]);

		// add entry to copy dict
		if (!dictionary_add_entry(copy_dict, copy_entry)) {
			// if copy_dict can not hold another entry, free the copy_entry.
			free(copy_entry);
		}
	}
	return copy_dict;
}

// This function merges dictionary b into dictionary a, creating a new
// dictionary.
inline dictionary *
dictionary_merge(dictionary *a, dictionary *b)
{
	// make a copy of a
	dictionary *new_dict = dictionary_copy(a);

	size_t i = 0;
	// for each entry in dict b
	for (; i < b->entry_cnt; i++) {
		dictionary_entry *copy_entry = dictionary_entry_copy((*b->entries)[i]);

		// add entry from dict b into new dictionary
		if (!dictionary_add_entry(new_dict, copy_entry)) {
			free(copy_entry);
		}
	}
	return new_dict;
}
/*
    This function parses a dictionary file, constructs a dictionary object,
and returns it.

    A dictionary file is of the form:

    foo="<a>"
    bar="<b>"
    baz="ELF"
    asdfdsafasdfasdf="LOL"

    Note: we actually ignore everything that's not in between quotes.

    This function handles \xNN escaping, \\, and \".

    A good chunk of this code is borrowed from AFL.
*/

inline dictionary *
dictionary_load_file(char *filename, size_t max_entries, size_t max_token_len)
{
	u8 buf[MAX_LINE];
	// points to left side of curr line
	u8 *lptr     = 0;
	u32 cur_line = 0;

	// use default max token len
	// theoretically, this function should only be used to construct
	// user-supplied dictionaries, as auto-dicts are ... auto.
	if (!max_token_len) {
		max_token_len = MAX_USER_DICT_ENTRY_LEN;
	}

	if (!max_entries) {
		max_entries = MAX_USER_DICT_ENTRIES;
	}
	dictionary *new_dict = dictionary_create(max_entries, max_token_len);

	FILE *file = fopen(filename, "r");
        printf("filename: %s\n", filename); 

	if (!file) {
		printf("file is null\n");
		exit(EXIT_FAILURE);
	}

	while ((lptr = (u8 *)fgets((char *)buf, MAX_LINE, file))) {

		// points to right side of curr line
		u8 *rptr = 0;
		cur_line++;

		// Trim on left and right
		while (isspace(*lptr))
			lptr++;

		rptr = lptr + strlen((char *)lptr) - 1;
		while (rptr >= lptr && isspace(*rptr))
			rptr--;
		rptr++;
		*rptr = 0;

		/* Skip empty lines and comments. */
		if (!*lptr || *lptr == '#' || *lptr == '\n')
			continue;

		/* All other lines must end with '"', which we can consume. */
		rptr--;

		if (rptr < lptr || *rptr != '"') {
			printf("Malformed name=\"value\" pair in line %u.", cur_line);
			exit(EXIT_FAILURE);
		}

		// null terminate the token
		*rptr = 0;

		/* Skip keyword, find opening quote */
		while (*lptr != '"' && lptr != rptr)
			lptr++;
		// if we could not find the opening quote
		if (lptr == rptr) {
			printf("Malformed name=\"keyword\" pair in line %u.", cur_line);
			exit(EXIT_FAILURE);
		}

		// consume opening ", lptr now points to our new token
		lptr++;

		if (!*lptr) {
			printf("Empty keyword in line %u.", cur_line);
			exit(EXIT_FAILURE);
		}
		// lptr now points to our new token, rptr points to the end of the token

		// allocate a new entry
		// new token
		// +1 to ensure null terminator
		u8 *new_token            = calloc(1, (unsigned long)(rptr - lptr));
		u8 *new_token_start_addr = new_token;

		/* Okay, let's copy data from lptr, handling \xNN escaping, \\, and \". */
		while (*lptr) {

			char *hexdigits = "0123456789abcdef";

			switch (*lptr) {

			case 1 ... 31:
			case 128 ... 255:
				printf("Non-printable characters in line %u.", cur_line);
				exit(EXIT_FAILURE);

			case '\\':

				lptr++;

				if (*lptr == '\\' || *lptr == '"') {
					*(new_token++) = *(lptr++);
					break;
				}

				if (*lptr != 'x' || !isxdigit(lptr[1]) || !isxdigit(lptr[2])) {
					printf("Invalid escaping (not \\xNN) in line %u.", cur_line);
					exit(EXIT_FAILURE);
				}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdisabled-macro-expansion"
				*(new_token++) =
				    (u8)(((strchr(hexdigits, tolower(lptr[1])) - hexdigits) << 4) |
				         (strchr(hexdigits, tolower(lptr[2])) - hexdigits));
#pragma clang diagnostic pop
				lptr += 3;
				break;

			default:
				*(new_token++) = *(lptr++);
			}
		}
		// create a new entry
		dictionary_entry *new_entry = dictionary_entry_create(new_token_start_addr);

		// no longer need this buffer, as it's been copied into new_entry
		free(new_token_start_addr);

		if (!dictionary_add_entry(new_dict, new_entry)) {
			free(new_entry);
		}
	}
	return new_dict;
}

// This function serializes a dictionary into a string.

inline char *
dictionary_serialize(dictionary *dict)
{
	char **s_entries = calloc(1, sizeof(char *) * (dict->entry_cnt));
	char  *s_dict    = NULL;

	yaml_serializer *helper = yaml_serializer_init("");
	size_t           mybuffersize;
	u32              version = 0;

	// We want to name the structure for readability
	YAML_SERIALIZE_NEST_MAP(helper, dictionary)
	YAML_SERIALIZE_START_MAPPING(helper)
	YAML_SERIALIZE_32HEX_KV(helper, version, version)

	YAML_SERIALIZE_64HEX_PSTRUCT(helper, dict, max_entry_cnt)
	YAML_SERIALIZE_64HEX_PSTRUCT(helper, dict, max_token_len)

	YAML_SERIALIZE_STRUCT_ARRAY(helper, (*dict->entries), entries, dict->max_entry_cnt, SERIALIZE_DICTIONARY_ENTRY)

	YAML_SERIALIZE_END_MAPPING(helper)
	yaml_serializer_end(helper, &s_dict, &mybuffersize);

	free(s_entries);

	return s_dict;
}

// Yaml helper function to deserialize an individual dictionary entry
static void
dictionary_entry_deserialize_yaml(yaml_deserializer *helper, __attribute__((unused)) struct dictionary_entry **dict_entry, dictionary *dict)
{

	dictionary_entry *new_entry;

	YAML_DESERIALIZE_EAT(helper)

	if (helper->event.type == YAML_SEQUENCE_END_EVENT) {
		return;
	}

	new_entry = calloc(1, sizeof(dictionary_entry));

	YAML_DESERIALIZE_GET_KV_U64(helper, "len", &new_entry->len)
	YAML_DESERIALIZE_GET_KV_U64(helper, "hit_cnt", &new_entry->hit_cnt)

	new_entry->token = calloc(1, new_entry->len);

	// deserialize the token
	YAML_DESERIALIZE_SEQUENCE_U8(helper, "token", new_entry->token)

	if (!dictionary_add_entry(dict, new_entry)) {

		dictionary_entry_free(new_entry);
	}

	YAML_DESERIALIZE_MAPPING_END(helper)
}

// This function deserializes a dictionary.
dictionary *
dictionary_deserialize(char *s_dict, size_t s_dict_size)
{
	dictionary        *new_dict;
	size_t             max_entry_cnt = 0;
	size_t             max_token_len = 0;
	u32                version       = 0;
	yaml_deserializer *helper        = NULL;

	if (s_dict == NULL) {
		return NULL;
	}

	helper = yaml_deserializer_init(NULL, s_dict, s_dict_size);

	// Get to the document start
	YAML_DESERIALIZE_PARSE(helper)
	while (helper->event.type != YAML_DOCUMENT_START_EVENT) {
		YAML_DESERIALIZE_EAT(helper)
	}

	// Deserialize the dictionary structure:
	// This is coded like LL(1) parsing, not event-driven, because we only support one version of file_format_version and
	// no structure members are optional in the yaml file.

	YAML_DESERIALIZE_EAT(helper)
	YAML_DESERIALIZE_MAPPING_START(helper, "dictionary")

	// Deserialize the structure version. We have only one version, so we don't do anything with it.
	YAML_DESERIALIZE_GET_KV_U32(helper, "version", &version)

	YAML_DESERIALIZE_GET_KV_U64(helper, "max_entry_cnt", &max_entry_cnt)
	YAML_DESERIALIZE_GET_KV_U64(helper, "max_token_len", &max_token_len)

	new_dict = dictionary_create(max_entry_cnt, max_token_len);

	YAML_DESERIALIZE_SEQUENCE(helper, "entries", dictionary_entry_deserialize_yaml, (*new_dict->entries), new_dict)

	YAML_DESERIALIZE_MAPPING_END(helper)
	yaml_deserializer_end(helper);

	return new_dict;
}

#pragma clang diagnostic pop
