<!--
DISTRIBUTION STATEMENT A. Approved for public release. Distribution is unlimited.

This material is based upon work supported by the Department of the Air Force under Air Force Contract No. FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the Department of the Air Force.

© 2019 Massachusetts Institute of Technology.
 
Subject to FAR52.227-11 Patent Rights - Ownership by the contractor (May 2014)
 
The software/firmware is provided to you on an As-Is basis
 
Delivered to the U.S. Government with Unlimited Rights, as defined in DFARS Part 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed above. Use of this work other than as specifically authorized by the U.S. Government may violate any copyrights that exist in this work.
-->

## Running Tests
### How do I run the tests?
You need to run the `run.sh` script from **_this_** directory. You must have docker installed.
### This is taking a while!
That's a complaint, not a question.
### Why is this taking so long?
It has to create a docker container on the first run. It should be cached, so it only takes a while on the first run.
### What happened?
It should have run all of the tests and put them in a timestamped folder.

## Adding Tests
### How do I add a test?
Just update the `test_everything.sh` to include your tests. Make sure to forward your results to the `$results_folder`.
