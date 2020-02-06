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

// yaml_decoder
//
// Quick utility to parse a yaml file supplied on the command line, printing
// the stream of events and tokens returned by the yaml parser.
//
// Useful for decoding what a yaml file looks like to aid debugging your yaml code.
//
// Suggestion: Redirect the output of this program to a file, then edit the file
// to search for your areas of difficulty.
//
// J. Cook, December 2018

#include <stdio.h>
#include <yaml.h>

int
main(int argc, char **argv)
{

	FILE *        fh;
	yaml_parser_t parser;
	yaml_event_t  event;
	int           done     = 0;
	int           level    = 0;
	char *        indent[] = {" 1",
                          "   2",
                          "     3",
                          "       4",
                          "         5",
                          "           6",
                          "             7",
                          "               8",
                          "                 9"};

	if (argc < 2) {
		printf("Must provide filename.\n");
		exit(EXIT_FAILURE);
	}

	if ((fh = fopen(argv[1], "r")) == NULL) {
		printf("Failed to open file!\n");
		exit(EXIT_FAILURE);
	}

	// Init. parser
	if (!yaml_parser_initialize(&parser)) {
		printf("Failed to initialize yaml parser!\n");
		exit(EXIT_FAILURE);
	}

	// Set the input file
	yaml_parser_set_input_file(&parser, fh);

	// Keep acquring events and displaying them until the end.
	do {

		if (!yaml_parser_parse(&parser, &event)) {
			printf("Parser error %d\n", parser.error);
			exit(EXIT_FAILURE);
		}

		switch (event.type) {

		case YAML_NO_EVENT:
			printf("\nNo event!\n\n");
			break;

		case YAML_STREAM_START_EVENT:
			printf("\nSTREAM_START\n\n");
			break;

		case YAML_STREAM_END_EVENT:
			printf("\nSTREAM_END\n\n");
			done = 1;
			break;

		case YAML_DOCUMENT_START_EVENT:
			printf("\nStart Document\n\n");
			break;

		case YAML_DOCUMENT_END_EVENT:
			printf("\nEnd Document\n\n");
			break;

		case YAML_SEQUENCE_START_EVENT:
			printf("\n%s Start Sequence\n\n", indent[level]);
			level++;
			break;

		case YAML_SEQUENCE_END_EVENT:
			level--;
			printf("\n%s End Sequence\n\n", indent[level]);
			break;

		case YAML_MAPPING_START_EVENT:
			printf("\n%s Start Mapping\n\n", indent[level]);
			level++;
			break;

		case YAML_MAPPING_END_EVENT:
			level--;
			printf("\n%s End Mapping\n\n", indent[level]);
			break;

		case YAML_ALIAS_EVENT:
			printf("%s Alias: '%s'\n", indent[level], event.data.alias.anchor);
			break;

		case YAML_SCALAR_EVENT:
			printf("%s Scalar: '%s'\n", indent[level], event.data.scalar.value);
			break;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcovered-switch-default"

		default:

#pragma clang diagnostic pop

			// There are other types. Add them if we start using them.

			printf("\nUNKNOWN event type %d\n", event.type);
			exit(EXIT_FAILURE);
		}

		yaml_event_delete(&event);

	} while (!done);

	yaml_parser_delete(&parser);
	fclose(fh);
	return 0;
}
