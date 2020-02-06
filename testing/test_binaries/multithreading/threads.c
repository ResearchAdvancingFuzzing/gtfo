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

#include <windows.h>
#include <stdio.h>

DWORD CALLBACK
inc(LPVOID lpParameter)
{
	unsigned int ctr = 0;
	for (; ctr < 10000; ctr++) {
		;
	}
	return 0;
}

void
test()
{
	DWORD        tid = 0;
	unsigned int ctr = 0;
	int *        ptr = 0x41414141;
	HANDLE       h   = CreateThread(0, 0, inc, &ctr, 0, &tid);

	WaitForSingleObject(h, INFINITE);
	*ptr = 1;
	CloseHandle(h);
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
	my_pause();
	test();
	return 0;
}
