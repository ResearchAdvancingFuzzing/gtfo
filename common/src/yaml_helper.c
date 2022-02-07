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

#include "common/sized_buffer.h"
#include "common/yaml_helper.h"
#include <stdio.h>  // for fclose, fopen
#include <stdlib.h> // for free, calloc

// Initializes a yaml_serializer object
// If a null filename is provided, we will serialize to a buffer.
yaml_serializer *
yaml_serializer_init(char *outfile_name)
{
	yaml_serializer *helper = calloc(1, sizeof(yaml_serializer));
	size_t           len;

	if (outfile_name && (len = strlen(outfile_name)) != 0) {
		helper->outfile_name = calloc(1, len + 1);
		memcpy(helper->outfile_name, outfile_name, len);
		helper->outfile = fopen(helper->outfile_name, "wb");
	} else {
		helper->outfile = open_memstream(&(helper->memstream_buffer), &(helper->memstream_buffer_size));
	}

	YAML_SERIALIZE_INIT(helper)
	YAML_SERIALIZE_START_MAPPING(helper)
	return helper;
}

// Destroys a yaml_serializer_object & return serialized buffer if null file
// Note: caller must free returned buffer.
void
yaml_serializer_end(yaml_serializer *helper, char **buffer, size_t *buffer_size)
{
	YAML_SERIALIZE_END_MAPPING(helper)
	YAML_SERIALIZE_END(helper)
	fclose(helper->outfile); // This will flush & update the buffer pointer,size.
	free(helper->outfile_name);

	if (buffer) {
		*buffer = helper->memstream_buffer;
	}
	if (buffer_size) {
		*buffer_size = helper->memstream_buffer_size;
	}

	free(helper);
}

// Initializes a yaml_deserializer object to read from a file or buffer
// Caller either supplies a filename, or a buffer and size.
yaml_deserializer *
yaml_deserializer_init(char *infile, char *buffer, size_t buffer_size)
{
	yaml_deserializer *helper = calloc(1, sizeof(yaml_deserializer));
	yaml_parser_initialize(&helper->parser);

	if (infile) {

		size_t len          = strlen(infile);
		helper->infile_name = calloc(1, len + 1);
		memcpy(helper->infile_name, infile, len);

		helper->infile = fopen(helper->infile_name, "rb");

		yaml_parser_set_input_file(&helper->parser, helper->infile);

	} else {

		helper->buffer      = buffer;
		helper->buffer_size = buffer_size;

		yaml_parser_set_input_string(&helper->parser, (u8 *)helper->buffer, helper->buffer_size);
	}

	return helper;
}

// destroys a yaml_deserializer object.
void
yaml_deserializer_end(yaml_deserializer *helper)
{
	yaml_parser_delete(&helper->parser);
	if (!helper->buffer) {
		fclose(helper->infile);
		free(helper->infile_name);
	}
	free(helper);
}
