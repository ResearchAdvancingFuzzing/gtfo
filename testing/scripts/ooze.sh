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

echo "[+] Beginning ooze testing!"

virt=$(systemd-detect-virt --container)
if [ $virt != "docker" ]; then

  gtfo_dir=$(expr "$PWD" : '\(.*gtfo\)')

  echo -e "\nOperating out of $gtfo_dir"

  if [ -n "$1" ]; then
    strategy_list=$1
  else
    strategy_list=$gtfo_dir/testing/tap_tester/tap_tests/ooze/*
  fi

  echo -e "Using $gtfo_dir/testing/tap_tester/build\n"
  mkdir -p $gtfo_dir/testing/tap_tester/build
  pushd $gtfo_dir/testing/tap_tester/build

  for strategy_dir in $strategy_list; do
    strategy=$(basename $strategy_dir)
    if [[ $strategy != "sage_test" ]]; then
      echo "[+] Testing $strategy strategy."

      # There may be multiple versions depending on where things are built. Force the user to choose
      F1=$gtfo_dir/build/ooze/strategies/src/strategies/$strategy/$strategy.so
      F2=$gtfo_dir/ooze/build/strategies/src/strategies/$strategy/$strategy.so
      if [[ -f $F1 && -f $F2 ]]; then
        echo -e "Cannot choose between .so files. Delete one:\n  $F1\n  $F2\n"
        exit 1
      fi

      if [[ -f $F1 ]]; then
        $gtfo_dir/testing/tap_tester/build/ooze_tap $F1 $gtfo_dir/testing/tap_tester/tap_tests/ooze/$strategy/testfile.txt
      elif [[ -f $F2 ]]; then
        $gtfo_dir/testing/tap_tester/build/ooze_tap $F2 $gtfo_dir/testing/tap_tester/tap_tests/ooze/$strategy/testfile.txt
      else
        echo -e "Cannot find either:\n  $F1\n  $F2\n"
        exit 1
      fi

      echo -e "[+] Done with $strategy!\n"
    fi
  done

  popd
  exit 0
else

  mkdir -p /home/ooze/make
  mkdir $1/ooze

  pushd /home/ooze/make 1>/dev/null

  echo "[+] Compiling..."
  CC=clang cmake -DCMAKE_BUILD_TYPE=debug .. 1>/dev/null 2>/dev/null
  make 1>$1/ooze/ooze_build_stdout.txt 2>$1/ooze/ooze_build_stderr.txt
  echo "[+] Done!"
  popd 1>/dev/null

  for strategy_dir in /home/ooze/make/strategies/src/strategies/*; do
    strategy=$(basename $strategy_dir)
    if [[ $strategy != "sage_test" ]]; then
      echo "[+] Testing $strategy strategy."

      ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-6.0/bin/llvm-symbolizer ASAN_OPTIONS=halt_on_error=false:detect_odr_violation=0 /home/testing/tap_tester/make/ooze_tap /home/ooze/make/strategies/src/strategies/$strategy/$strategy.so /home/testing/tap_tester/tap_tests/ooze/$strategy/testfile.txt 1>$1/ooze/${strategy}_stdout.txt 2>$1/ooze/${strategy}_stderr.txt
      echo "[+] Done!"
    fi
  done

  echo "[+] Ooze testing complete! cleaning up..."
  rm -rv /home/ooze/make 1>/dev/null 2>/dev/null
  echo "[+] Done!"
  echo ""

fi
