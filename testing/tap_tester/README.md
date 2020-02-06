<!--
(DISTRIBUTION STATEMENT A. Approved for public release. Distribution is unlimited.)

(This material is based upon work supported by the Department of the Air Force under Air Force Contract No. FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the Department of the Air Force.)

(© 2019 Massachusetts Institute of Technology.)
()
(Subject to FAR52.227-11 Patent Rights - Ownership by the contractor (May 2014))
()
(The software/firmware is provided to you on an As-Is basis)
()
(Delivered to the U.S. Government with Unlimited Rights, as defined in DFARS Part 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed above. Use of this work other than as specifically authorized by the U.S. Government may violate any copyrights that exist in this work.)
-->

This is a set of test harnesses that produce TAP messages (http://testanything.org) for ooze, analysis, and jigs.
Here's a brief breakdown of the files here:

	/analysis - the code necessary to interface with analysis modules
	/jig - the code necessary to interface with jig modules
	/ooze - the code necessary to interface with ooze modules
	/tap - the code that handles the TAP format
	/testfile - the code that parses our testfiles
	/tap_tests - the testfiles for the various modules (note that analysis modules don't take testfiles at the moment)


The testfile format is as follows:

[Testfile Version]

["ENVS" followed by a "environment variable"="value"]

[a test harness dependent meta line]
the tests to run
