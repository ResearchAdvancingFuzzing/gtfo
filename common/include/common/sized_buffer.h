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
#include "stdbool.h"
#include "common/types.h"

/*
	This header file and its sibling .c file provide common functions used by
	multiple Nocturne plugins.
*/

/*
	A sized buffer is simply a chunk of memory and an amount of content.
*/
typedef struct sized_buffer {
	u8 *   content;
	size_t content_size;
} sized_buffer;

sized_buffer *sized_buffer_create(void);
void          sized_buffer_free(sized_buffer *sized_buf);
bool          sized_buffer_insert(sized_buffer *sized_buf, u8 *input, size_t input_size);
void          sized_buffer_extract(sized_buffer *sized_buf, u8 **output, size_t *output_size);
void          sized_buffer_reset(sized_buffer *sized_buf);
