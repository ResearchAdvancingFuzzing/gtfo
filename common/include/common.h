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

#include "common/definitions.h"
#include "common/types.h"
#include "common/annotations.h"
#include "common/logger.h"
#include "common/sized_buffer.h"

#ifdef KVM_VMX_PT_SUPPORTED
#include <intel-pt.h>
#include "intel_pt/pt_cpu.h"
#include "intel_pt/pt_cpuid.h"
#include "intel_pt/pt_version.h"

int pt_inst_decode(uint8_t *trace_buffer, size_t trace_size, read_memory_callback_t *read_image_callback, void *context);
void pt_packet_decode(unsigned char *trace_buffer, size_t trace_size);
#endif
