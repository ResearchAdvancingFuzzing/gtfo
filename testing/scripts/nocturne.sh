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

echo "[+] Begin Nocturne Testing!"

mkdir -p /home/nocturne/make
mkdir $1/nocturne

pushd /home/nocturne/make 1>/dev/null

echo "[+] Compiling..."
CC=clang cmake -DCMAKE_BUILD_TYPE=debug .. 1>/dev/null 2>/dev/null
make 1>$1/nocturne/build_stdout.txt 2>$1/nocturne/build_stderr.txt
echo "[+] Done!"
popd 1>/dev/null

echo "[+] Running Nocturne Unit Tests..."
pushd /home/testing/tap_tester/make 1>/dev/null
if [ -f /home/nocturne/make/plugins/src/intel_pt/intel_pt.so ]; then
  echo "[+] intel_pt plugin detected."
  LOG_FILENAME=$1/nocturne/log_data.txt ./nocturne_kvm_tap /home/nocturne/make/plugins/src/breakpoint_single_step/breakpoint_single_step.so /home/nocturne/make/plugins/src/intel_pt/intel_pt.so 1>$1/nocturne/test_results_stdout.txt 2>$1/nocturne/test_results_stderr.txt
else
  LOG_FILENAME=$1/nocturne/log_data.txt ./nocturne_kvm_tap /home/nocturne/make/plugins/src/breakpoint_single_step/breakpoint_single_step.so 1>$1/nocturne/test_results_stdout.txt 2>$1/nocturne/test_results_stderr.txt
fi

rm -rv /home/nocturne/make 1>/dev/null 2>/dev/null
echo "[+] Done!"
popd 1>/dev/null
echo ""
