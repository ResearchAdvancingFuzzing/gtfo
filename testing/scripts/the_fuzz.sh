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

echo "[+] Begin the_fuzz testing!"

mkdir -p /home/the_fuzz/make
mkdir $1/the_fuzz

pushd /home/the_fuzz/make 1>/dev/null

echo "[+] Compiling..."
CC=clang cmake -DCMAKE_BUILD_TYPE=debug .. 1>/dev/null 2>/dev/null
make 1>$1/the_fuzz/build_stdout.txt 2>$1/the_fuzz/build_stderr.txt
echo "[+] Done!"
popd 1>/dev/null

pushd /home/testing/tap_tester/ 1>/dev/null
echo "[+] Testing analysis 'afl_bitmap'"
ANALYSIS_SIZE=64 ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-6.0/bin/llvm-symbolizer ASAN_OPTIONS=halt_on_error=false:detect_odr_violation=0 ./make/analysis_tap -A /home/the_fuzz/make/afl_bitmap_analysis.so -t /home/testing/tap_tester/tap_tests/analysis/afl/testfile.txt 1>$1/the_fuzz/analysis_afl_bitmap_stdout.txt 2>$1/the_fuzz/analysis_afl_bitmap_stderr.txt
echo "[+] Done!"
echo "[+] Testing analysis 'falk_filter'"
ANALYSIS_SIZE=12000 ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-6.0/bin/llvm-symbolizer ASAN_OPTIONS=halt_on_error=false:detect_odr_violation=0 ./make/analysis_tap -A /home/the_fuzz/make/falk_filter_analysis.so -t /home/testing/tap_tester/tap_tests/analysis/falk/testfile.txt 1>$1/the_fuzz/analysis_falk_filter_stdout.txt 2>$1/the_fuzz/analysis_falk_filter_stderr.txt
echo "[+] Done!"
echo "[+] Testing analysis 'intelpt hash'"
ANALYSIS_SIZE= ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-6.0/bin/llvm-symbolizer ASAN_OPTIONS=halt_on_error=false:detect_odr_violation=0 ./make/analysis_tap -A /home/the_fuzz/make/pt_hash_analysis.so -t /home/testing/tap_tester/tap_tests/analysis/intelpt/testfile.txt 1>$1/the_fuzz/analysis_intelpt_stdout.txt 2>$1/the_fuzz/analysis_intelpt_stderr.txt
echo "[+] Done!"
echo "[+] Testing analysis 'demo'"
ANALYSIS_SIZE=8 ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-6.0/bin/llvm-symbolizer ASAN_OPTIONS=halt_on_error=false:detect_odr_violation=0 ./make/analysis_tap -A /home/the_fuzz/make/demo_analysis.so -t /home/testing/tap_tester/tap_tests/analysis/demo/testfile.txt 1>$1/the_fuzz/analysis_intelpt_stdout.txt 2>$1/the_fuzz/analysis_intelpt_stderr.txt
echo "[+] Done!"
echo "[+] Testing jig 'afl'"
ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-6.0/bin/llvm-symbolizer ASAN_OPTIONS=halt_on_error=false:detect_odr_violation=0 JIG_MAP_SIZE=65536 JIG_TARGET=/home/testing/tap_tester/tap_tests/jig/tiff2rgba JIG_TARGET_ARGV="-c jpeg fuzzfile /dev/null" ./make/jig_tap -J /home/the_fuzz/make/afl_jig.so -t /home/testing/tap_tester/tap_tests/jig/afl/testfile.txt 1>$1/the_fuzz/jig_afl_stdout.txt 2>$1/the_fuzz/jig_afl_stderr.txt
echo "[+] Done!"
echo "[+] Testing jig 'dummy'"
ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-6.0/bin/llvm-symbolizer ASAN_OPTIONS=halt_on_error=false:detect_odr_violation=0 ./make/jig_tap -J /home/the_fuzz/make/dummy_jig.so -t /home/testing/tap_tester/tap_tests/jig/dummy/testfile.txt 1>$1/the_fuzz/jig_dummy_stdout.txt 2>$1/the_fuzz/jig_dummy_stderr.txt
echo "[+] Tests complete! cleaning up..."
popd 1>/dev/null

rm -rv /home/the_fuzz/make 1>/dev/null 2>/dev/null
rm /home/testing/tap_tester/tap_tests/jig/afl/fuzzfile 2>/dev/null
echo "[+] Done!"
echo ""
