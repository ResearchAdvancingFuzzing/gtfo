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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
// copied from the SAGE paper [citation needed]
void
test(char input[4])
{
	int cnt = 0;
	if (input[0] == 'b') {
		cnt++;
	}
	if (input[1] == 'a') {
		cnt++;
	}
	if (input[2] == 'd') {
		cnt++;
	}
	if (input[3] == '!') {
		cnt++;
	}
	if (cnt >= 4) {
		int *ptr = NULL;
		ptr      = (int *)0x4141414141414141;
		*ptr     = 1;
	}
}

void
my_pause()
{
	puts("Press any character to continue");
	getchar();
}

int
main(int argc, char *argv[])
{
	FILE *input_file;
	char  input[4];
	my_pause();

	if (argc == 2) {
		input_file = fopen(argv[1], "r");
	} else {
		input_file = stdin;
	}

	int c;
	for (unsigned int i = 0; i < 4; i++) {
		c = fgetc(input_file);
		if (c == EOF) {
			perror("hit EOF\n");
			exit(1);
		}
		input[i] = (char)c;
	}

	test(input);
	return 0;
}
