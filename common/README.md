<!--
DISTRIBUTION STATEMENT A. Approved for public release. Distribution is unlimited.

This material is based upon work supported by the Department of the Air Force under Air Force Contract No. FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the Department of the Air Force.

© 2019 Massachusetts Institute of Technology.
 
Subject to FAR52.227-11 Patent Rights - Ownership by the contractor (May 2014)
 
The software/firmware is provided to you on an As-Is basis
 
Delivered to the U.S. Government with Unlimited Rights, as defined in DFARS Part 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed above. Use of this work other than as specifically authorized by the U.S. Government may violate any copyrights that exist in this work.
-->

# Common

A convenient repository for library functions usable across internals, plugins, tests, and user code. This project compiles to a shared library called 'gtfo_common.so'.

## Dependencies

This library depends on Intel's libipt and libxed libraries.

If these dependencies are not installed, 'gtfo_common.so' will still build, but with limited functionality.

##### Intel libipt

```shell script
git clone https://github.com/intel/libipt; cd libipt; mkdir build; cd build; CC=clang cmake ..; make; sudo make install; cd ..;

```

##### Intel libxed
```shell script
git clone https://github.com/intelxed/xed; git clone https://github.com/intelxed/mbuild.git; cd xed; ./mfile.py --shared install;
sudo cp kits/xed-install-base-2019-09-25-lin-x86-64/lib/libxed.so /usr/local/lib/;
sudo cp -r kits/xed-install-base-2019-09-25-lin-x86-64/include/xed /usr/local/include;
cd ../;
```

## Building and Installing

If you run `make install` in your build directory, this library will be installed as '/usr/local/lib/libgtfo_common.so' on Linux systems.

## APIs

This library is a collection of utility subsystems. API descriptions are grouped below by subsystem.

Software utilizing this library may include '/usr/local/gtfo/include/common.h', which includes all subsystem header files, or may include just the individual header file(s) of a subsystem of interest.

### Logging

Messages are logged to a file or stdout using a printf-like interface after prepending a severity-level character and the module #define name. 

#### init_logging
```c
void init_logging(void);
```

##### Description

This function initializes logging. By default,logging is sent to `stdout`. If an environment variable named `LOG_FILENAME` is set, output will be sent to the specified filename. Additionally, the `LOG_DEBUG_MODULE` environment variable can be defined. This environment variable is used in the `log_debug()` function.


#### output
```c
void output(char *msg, ...);
```

##### Description

This function simply outputs `msg` in a _printf_-like fashion. 

#### log_info
```c
void log_info(char *msg, ...);
```
##### Description
This function behaves similarly to the `output()` function described above.
 
Additionally, this function prepends the characters `[+]` and the `MODULE` that has initialized the logger:

```text
[+] MODULE: <printf message>
```
 
As an example, if the "the_fuzz" project contained the following line:
```c 
 log_info("It's all good in the neighborhood!");
```

Our `MODULE` is "the_fuzz" and the resultant output would look like this:

```text
[+] the_fuzz: It's all good in the neighborhood!
```

#### log_warn
```c
void log_warn(char *msg, ...);
```

##### Description
Similar to `output()` and `log_info()` above, but `[!]` is now prepended:

```text
[!] MODULE: <printf message>
```

#### log_fatal
```
_Noreturn void log_fatal(char *msg, ...);
```
##### Description

Similar to `log_info()`, but `[X]` is now prepended and the program is terminated:  

```text
[X] MODULE: <printf message>
```

#### log_debug
```c
void log_debug(char *msg, ...);
```
##### Description
Similar to `log_info()` above, but `[?]` is now prepended.

```text
[?] MODULE: <printf message>
```

This function will only produce output if the `LOG_DEBUG_MODULE` environment variable was set during `init_logging()`.

The `MODULE` string must be a substring of `LOG_DEBUG_MODULE`.

#### log\_report\_seed
```c
void log_report_seed(char *seed);
```
##### Description
Similar to _log\_info_ above, but`[S]` is prepended:

```text
[S] MODULE: <printf message>
```

#### log\_report\_crash
```c
void log_report_crash(char *crash);
```

##### Description
Similar to _log\_info_ above, but `[C]` is prepended:   
```text
[C] MODULE: <printf message>
```
 
### CPUID Functions

These are simple support functions to identify the cpu type and version as required by Intel processor trace decode functions.
Mention is made here only to note their availability. As their implementation is relatively straightforward, see the code for further details:

cpu.h: 

```c
int pt_cpu_read(struct pt_cpu *cpu);
```  

cpuid.h:
```c
void pt_cpuid(uint32_t leaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx);
```


### Intel Processor Trace Decoders 

#### pt_packet_decode
```c
void pt_packet_decode(unsigned char *trace_buffer, size_t trace_size)
```

##### Description
Given a buffer of trace data produced by Intel's Processor Trace hardware feature, this function will decode and print the stream of trace packet types and their byte offset within the buffer. Further information on packet types can be found in 'Intel 64 and IA-32 Architectures Software Developer's Manual Volume 3, Chapter 35' 

Example decoded trace data generated by a custom tap test:

```text
...

Extract call returned true 0x266b630 70976.


Intel processor trace PACKET decode results:
0       psb
10      pad
11      pad
12      pad
13      mode.tsx
15      mode.exec lma=0 cs.d=1
17      fup     3: 116dd0
1e      pad
1f      pad
20      pad
21      pad
22      pad
23      pad
24      pad
25      pad
26      pip     7274000
2e      pad
2f      pad
30      pad
31      pad
32      pad
33      pad
34      pad
35      pad
36      vmcs    86c803000
3d      pad
3e      pad
3f      pad
40      cbr     33
44      psbend
46      pad
47      tip.pge 3: 116dd0

...
```

__Note:__ `pt_packet_decode()` is contained in 'fastdecode.c', which was sourced from 'github.com/andikleen/simple-pt' in July 2019 and still contains Intel headers.
It was slightly modified to be present this call interface instead of a `main()` function to produce a command.
It should therefore be relatively easy to update with a new source pull from github.


#### Instruction Stream Decode
```c
int pt_inst_decode(uint8_t *trace_buffer, size_t trace_size, read_memory_callback_t *read_image_callback, void *context);

typedef int (read_memory_callback_t)(uint8_t *buffer, size_t size, const struct pt_asid *asid, uint64_t ip, void *context);
```

##### Description

Decodes and prints an instruction stream based on the supplied Intel hardware processor trace data buffer together with original binary program data. The trace data to be decoded is contained in `trace_buffer`. `pt_packet_decode()` will call the user supplied `read_image_callback()` function with the supplied `context` to obtain `size` bytes of the program traced at address `ip` as loaded in its original load/mapping location.

Example decoded trace data generated by a custom tap test:

```text
...

Intel processor trace INSTRUCTION decode results:
ok 180 - VM restored.

[enabled]
[disabled]
[resumed]
[disabled]
[resumed]
[disabled]
[resumed]
[disabled]
[resumed]
[disabled]
[resumed]
0000000000116dd0  push ebp
0000000000116dd1  mov ebp, esp
0000000000116dd3  sub esp, 0x8
0000000000116dd6  mov dword ptr [ebp-0x4], 0x0
0000000000116ddd  mov al, byte ptr [ebp+0x8]
0000000000116de0  mov byte ptr [ebp-0x8], al
0000000000116de3  cmp byte ptr [ebp-0x8], 0x41
0000000000116de7  jz 0x116df1
0000000000116de9  cmp byte ptr [ebp-0x8], 0x6e
0000000000116ded  jz 0x116e03
0000000000116e03  mov dword ptr [ebp-0x4], 0x0
0000000000116e0a  mov edx, dword ptr [ebp-0x4]
[disabled]
0000000000116e0a  mov edx, dword ptr [ebp-0x4]

...
```