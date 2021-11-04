#!/usr/bin/env bash
# DISTRIBUTION STATEMENT A. Approved for public release. Distribution is unlimited.
#
# This material is based upon work supported by the Department of the Air Force under Air Force Contract No. FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the Department of the Air Force.
#
# © 2019 Massachusetts Institute of Technology.
#
# Subject to FAR52.227-11 Patent Rights - Ownership by the contractor (May 2014)
#
# The software/firmware is provided to you on an As-Is basis
#
# Delivered to the U.S. Government with Unlimited Rights, as defined in DFARS Part 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed above. Use of this work other than as specifically authorized by the U.S. Government may violate any copyrights that exist in this work.

virt=$(systemd-detect-virt --container)
if [ $virt != "docker" ]; then
  echo "[-]This script can only be run in the docker container" 1>&2
  exit 1
fi

results_dir=$(date "+%Y.%m.%d.%H.%M.%S")
results_folder=/home/testing/test_results_$results_dir
mkdir -p $results_folder

echo "[+] Compiling TAP testers..."
mkdir -p /home/testing/tap_tester/make
pushd /home/testing/tap_tester/make >/dev/null 2>/dev/null
CC=clang cmake -DCMAKE_BUILD_TYPE=debug .. 1>$results_folder/tap_build_stdout.txt 2>$results_folder/tap_build_stderr.txt
make 1>/dev/null 2>/dev/null
popd 1>/dev/null
echo "[+] Done!"

####	Add test scripts below here	####
echo "------------------------------------------------------------"
/home/testing/scripts/the_fuzz.sh $results_folder
echo "------------------------------------------------------------"
/home/testing/scripts/ooze.sh $results_folder
echo "------------------------------------------------------------"

echo "[+] Testing complete, performing final cleanup..." 1>&2
rm -rv /home/testing/tap_tester/make 1>/dev/null 2>/dev/null
rm -rf /home/common/build/

# delete any empty test result files that were created.
find $results_folder/ -size 0 -print0 | xargs -0 rm
echo "[+] Done!" 1>&2

echo [+] Your results have been saved to ./test_results_$results_dir/
echo

echo [+] The following output files contain failed unit tests:
echo "------------------------------------------------------------"
grep -Rl "not ok" $results_folder/ 1>&2
echo "------------------------------------------------------------"
echo

echo [+] The following output files contain incomplete unit tests:
echo "------------------------------------------------------------"
grep -Rl "Bail out!" $results_folder/ 1>&2
echo "------------------------------------------------------------"
echo

echo [+] The following output files contain an error:
echo "------------------------------------------------------------"
grep -Rl "ERROR" $results_folder/ 1>&2
echo "------------------------------------------------------------"
echo


echo [+] A fatal error occured when generating the following output files
echo "------------------------------------------------------------"
grep -Rl "\[X\]" $results_folder/ 1>&2
echo "------------------------------------------------------------"

