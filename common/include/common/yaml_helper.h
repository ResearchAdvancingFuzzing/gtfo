#ifndef COMMON_YAML_HELPER_H
#define COMMON_YAML_HELPER_H

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

#include "common/yaml_deserializer.h"
#include "common/yaml_serializer.h"

yaml_serializer *yaml_serializer_init(char *outfile_name);
void             yaml_serializer_end(yaml_serializer *helper, char **buffer, size_t *buffer_size);

yaml_deserializer *yaml_deserializer_init(char *infile, char *buffer, size_t buffer_size);
void               yaml_deserializer_end(yaml_deserializer *helper);

#endif
