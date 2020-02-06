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

#include "common.h"
#include <stdlib.h> // for free
#include <string.h>

// create a 'sized_buffer' object.
sized_buffer *
sized_buffer_create()
{
	return (sized_buffer *)calloc(1, sizeof(sized_buffer));
}

// free a 'sized_buffer' object.
void
sized_buffer_free(sized_buffer *sized_buf)
{
	if (sized_buf->content) {
		free(sized_buf->content);
	}
	free(sized_buf);
}

// given a input and a size, copy the input to the sized_buf.
bool
sized_buffer_insert(sized_buffer *sized_buf, u8 *input, size_t input_size)
{
	if (!input) {
		log_warn("sized_buffer_save: in pointer value was %p", input);
	}

	else if (!input_size) {
		log_warn("sized_buffer_save: in_size was 0x%lx", input_size);
	}

	else {
		sized_buf->content = realloc(sized_buf->content, sized_buf->content_size + input_size + 1);
		// append new results
		memcpy((u8 *)((u64)sized_buf->content + (u64)sized_buf->content_size), input, input_size + 1);
		sized_buf->content_size += input_size;
		return true;
	}
	return false;
}

// provides the sized_buffer's content and amount of content back to the user.
void
sized_buffer_extract(sized_buffer *sized_buf, u8 **output, size_t *output_size)
{
	*output      = sized_buf->content;
	*output_size = sized_buf->content_size;
}

// reset a sized_buffer
void
sized_buffer_reset(sized_buffer *sized_buf)
{
	sized_buf->content_size = 0;
}
