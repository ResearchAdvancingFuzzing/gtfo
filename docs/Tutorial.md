# Fuzzing libTIFF 3.7.0 with GTFO's AFL Jig: A Play in Three Acts
You can skip acts 1 and 2 if you're using the Docker image. You'll need to create a directory and replace `[WORK_DIR]` with its path. If you're going to use the Docker image, the `[WORK_DIR]` is `/fuzzer`. When building the Docker image, you need a checkout of the GTFO repo in the current working directory named `gtfo` for the `COPY` on line 23.

## Act 1: Getting AFL
We need AFL to add its coverage instrumentation to libTIFF. Run the following command to setup AFL:
```
cd [WORK_DIR]
wget http://lcamtuf.coredump.cx/afl/releases/afl-2.52b.tgz
tar xvf afl-2.52b.tgz
cd afl-2.52b
make
cd [WORK_DIR]
```

## Act 2: Building libTIFF
We need to compile an old version of libTIFF with AFL's instrumentation. **WARNING:**This will install a vulnerable version of libTIFF. 
```
cd [WORK_DIR]
wget https://download.osgeo.org/libtiff/old/tiff-3.7.0.tar.gz
tar xvf tiff-3.7.0.tar.gz
cd tiff-3.7.0
CFLAGS="-static -fno-PIE -fno-PIC" CC=[WORK_DIR]/afl-2.52b/afl-clang ./configure --enable-shared=no
RUN CFLAGS="-static -fno-PIE -fno-PIC" CC=[WORK_DIR]/afl-2.52b/afl-clang make
make install
```

## Act 3: Fuzzing with GTFO
Now we'll build GTFO. First, we'll build the mutations in ooze.
```
cd [WORK_DIR]
mkdir -p build/ooze build/the_fuzz gtfo
cd [WORK_DIR]/build/ooze
CC=clang cmake -DCMAKE_INSTALL_PREFIX=[WORK_DIR]/gtfo ../../ooze/
make
make install
```

Next we'll build the main interface, the jig, and the analysis. One day, these might be built separately.
```
cd [WORK_DIR]/build/the_fuzz
CC=clang cmake -DCMAKE_INSTALL_PREFIX=[WORK_DIR]/gtfo ../../the_fuzz/
make
make install
cd [WORK_DIR]
```

Here's the arcane incantation to launch the fuzzer.
```
LD_LIBRARY_PATH=[WORK_DIR]/gtfo/lib/ ANALYSIS_SIZE=65536 JIG_MAP_SIZE=65536 JIG_TARGET=/usr/local/bin/tiff2rgba  JIG_TARGET_ARGV="-c jpeg fuzzfile /dev/null" [WORK_DIR]/gtfo/bin/the_fuzz -S [WORK_DIR]/gtfo/gtfo/analysis/afl_bitmap_analysis.so -O [WORK_DIR]/gtfo/gtfo/ooze/afl_havoc.so -J [WORK_DIR]/gtfo/gtfo/the_fuzz/afl_jig.so -i [WORK_DIR]/libtiff_working/afl-2.52b/testcases/images/tiff/not_kitty.tiff -n inf -x 1024 -c bitmap -s `head -c 10 /dev/urandom | xxd -p`
```

We should see two directories created, `interesting` which stores crashes and `coverage` which stores inputs with new coverage. We can verify a crash with the following command
```
/usr/local/bin/tiff2rgba -c jpeg [WORK_DIR]/interesting/crash/[Some Crash].input /dev/null
```

Now, let's explain the above incantation:

	* LD_LIBRARY_PATH=[WORK_DIR]/gtfo/lib/
    	* This is just to tell the loader where our libraries are.
  	* ANALYSIS_SIZE=65536
    	* The size of AFL's coverage bitmap defaults to 65536 bytes, but it can be changed.
  	* JIG_MAP_SIZE=65536
    	* The jig is seperate from the analysis and needs to know the coverage bitmap size too.
  	* JIG_TARGET=/usr/local/bin/tiff2rgba
    	* The path to the program under test.
  	* - JIG_TARGET_ARGV="-c jpeg fuzzfile /dev/null"
    	* The arguments to the program under test. The jig will put the generated input in a file called `fuzzfile`.
  	* [WORK_DIR]/gtfo/bin/the_fuzz
    	* The interface binary
  	* -S [WORK_DIR]/gtfo/gtfo/analysis/afl_bitmap_analysis.so
		* The analysis plugin to use
	* -O [WORK_DIR]/gtfo/gtfo/ooze/afl_havoc.so
    	* The mutation engine to use
  	* -J [WORK_DIR]/gtfo/gtfo/the_fuzz/afl_jig.so
    	* The jig to use
  	* -i [WORK_DIR]/libtiff_working/afl-2.52b/testcases/images/tiff/not_kitty.tiff
    	* The initial input to mutate
  	* -n inf
    	* The number of iterations to run. It accepts `inf` as an option to run forever.
  	* -x 1024
    	* The maximum input size in bytes
  	* -c bitmap	
    	* The file to save the analysis results to after the fuzzer is done
  	* -s `head -c 10 /dev/urandom | xxd -p`
    	* The seed to use for the PRNG


