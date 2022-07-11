#include "common.h"
#include <stdbool.h>
#include "common/afl_config.h"
#ifndef ANALYSIS_AUTO_H
#define ANALYSIS_AUTO_H

typedef struct optional_args {
	u8* orig_buffer;
	size_t orig_size;
	size_t cur_pos;
} optional_args;

#endif
