<!--
DISTRIBUTION STATEMENT A. Approved for public release. Distribution is unlimited.

This material is based upon work supported by the Department of the Air Force under Air Force Contract No. FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the Department of the Air Force.

© 2019 Massachusetts Institute of Technology.
 
Subject to FAR52.227-11 Patent Rights - Ownership by the contractor (May 2014)
 
The software/firmware is provided to you on an As-Is basis
 
Delivered to the U.S. Government with Unlimited Rights, as defined in DFARS Part 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed above. Use of this work other than as specifically authorized by the U.S. Government may violate any copyrights that exist in this work.
-->

# The Generalizable Testbed for Fuzzing Operations

The Generalizable Testbed for Fuzzing Operations (GTFO) is a collection of modular components that are designed to be used together to conduct fuzz testing.

## Core Components

1. 'common/' - A Library containing common C Definitions, objects, and code used by other components, including logging  and Intel processor trace data decoding.
2. 'ooze/' - A collection of modular input generation strategies for use in fuzz testing.
3. 'the_fuzz/' - Our core fuzzer. It conducts fuzz testing, provides a UI, and performs crash detection and reporting.

## Building & Installing

Building requires clang-3.9+ and cmake 3.5+ on Linux.
 
Supported Operating System: Ubuntu 18.04.1 LTS

Building on MacOS, Linux with gcc, or on Windows by using Cygwin are no longer supported.

### Dependencies

#### Apt Dependencies
```shell script
sudo apt-get install libc6-dev clang cmake build-essential pkg-config libyaml-0-2 libyaml-dev python-yaml
```

Additionally, the following two dependencies should be installed for gtfo's common library.

If these dependencies are not installed, gtfo's common library will still build, but with limited functionality.

#### Intel libipt
```shell script
git clone https://github.com/intel/libipt; cd libipt; mkdir build; cd build; CC=clang cmake ..; make; sudo make install; cd ..;

```

#### Intel libxed
```shell script
git clone https://github.com/intelxed/xed; git clone https://github.com/intelxed/mbuild.git; cd xed; ./mfile.py --shared install;
sudo cp kits/xed-install-base-2019-09-25-lin-x86-64/lib/libxed.so /usr/local/lib/;
sudo cp -r kits/xed-install-base-2019-09-25-lin-x86-64/include/xed /usr/local/include;
cd ../;
```

#### Pip Dependencies
```shell script
pip install ply scipy numpy

```

### General Build

The entire gtfo source tree is built via:

```shell script
cd gtfo
./build.sh
```

To build a debug version of everything:

```shell script
cd gtfo
./build.sh -DCMAKE_BUILD_TYPE=Debug
```

#### Installation

General build output files are located in 'gtfo/build'. They may be installed by the following bash command:

```shell script
gtfo/build; make install;
```
The default install locations for files destined for directories such as bin, include, lib, etc. is '/usr/local/bin', '/usr/local/include', '/usr/local/lib', etc.

Use of '/usr/local' can be overridden by setting DESTDIR like so:
 
```shell script
make DESTDIR=/home/john install;
```

This is preferable to changing the value of `$CMAKE_INSTALL_PREFIX`.


##### Specific Subsystem Builds

Like any good build system, gtfo is structured to facilitate building individual subsystems. This is particularly useful when focusing on developing changes to a subsystem where it would be counterproductive to rebuild the entire build tree with each source code edit.

Any subsystem directory that contains a _CMakeLists.txt_ file is individually buildable. Build steps are the creation of a _build_ directory and processing the cmake file if this is the first time, then running the _make_ command. For example, if we were enhancing the _afl\_bit\_flip_ mutation, the first debug build of this subsystem would be:

```shell script
	cd gtfo/ooze/strategies/src/strategies/afl_bit_flip
	mkdir build
	CC=clang cmake .. -DCMAKE_BUILD_TYPE=Debug
	make
```

The output of the build will be contained in the local build directory, not gtfo/build/...