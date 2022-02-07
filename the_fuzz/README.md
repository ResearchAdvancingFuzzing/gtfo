<!--
(DISTRIBUTION STATEMENT A. Approved for public release. Distribution is unlimited.)

(This material is based upon work supported by the Department of the Air Force under Air Force Contract No. FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the Department of the Air Force.)

(© 2019 Massachusetts Institute of Technology.)
 
(Subject to FAR52.227-11 Patent Rights - Ownership by the contractor (May 2014))
 
(The software/firmware is provided to you on an As-Is basis)
 
(Delivered to the U.S. Government with Unlimited Rights, as defined in DFARS Part 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed above. Use of this work other than as specifically authorized by the U.S. Government may violate any copyrights that exist in this work.)
-->

# The Fuzz

This is the beginning of the fuzz 2.0. Here's a rough sketch of how it's going to work.

```text
                             +-------------------+
                             |                   |
          +------------->    |      target       |    <----------+
          |                  |                   |               |
          |                  +-------------------+               |
          |                                                      |
          |                                                      |
          |                                                      |
==========+====================== hypervisor ====================+==============
          |                                                      |
        direct                                                 direct
        memory                                                 memory
     manipulation                                           manipulation
          |                                                      |
          |                                                     \|/
         \|/                                           +-------------------+
+-------------------+                                  |                   |
|                   |                                  |       runner      |
|        jig        |    <---- shared library ---->    |        via        |
|                   |                                  |        KVM        |
+-------------------+                                  |                   |
                                                       +-------------------+
                                                                /|\
                                                                 |
                                                                 |
                                                              shared
                                                              library
                                                                 |
                                                                 |
                                                                \|/
+-------------------+                                  +-------------------+
|                   |                                  |                   |
|        ooze       |    <---- shared library ---->    |      the fuzz     |
|                   |                                  |                   |
+-------------------+                                  +-------------------+
                                                                /|\
                                                                 |
                                                                 |
                                                              shared
                                                              library
                                                                 |
                                                                 |
                                                                \|/
                                                       +-------------------+
                                                       |                   |
                                                       |      analysis     |
                                                       |                   |
                                                       +-------------------+

```

# Components

| Component | Description |
|-----------|-------------|
|analysis | An efficient analysis layer for seeing if a run has new coverage.|
|the fuzz | The glue that holds everything together, provides a UI, and reporting.|
|jig| Takes the new input from ooze, performs a single fuzz test, and returns results.|

# APIs

## Analysis

Provides an internal analysis for the fuzz (like the AFL bitmap).

```c
void (*get_analysis_api)(analysis_api *s);
```

Each analysis provides this global function pointer.

Use this function to obtain an instance of an analysis' API.

The API object provides the following variables:

```c
const char * name; // The name of the analysis.
const char * description; // A description of the analysis.
```

### Analysis API Functions

#### analysis_add_function

```c
bool analysis_add_function(u8 *element, size_t element_size);
```

##### Arguments

##### Returns

##### Description

#### analysis_init_function

```c
void analysis_init_function(char *filename);
```

##### Arguments

##### Returns

##### Description

#### analysis_save_function

```c
void analysis_save_function(char *filename);
```

##### Arguments

##### Returns

##### Description

#### analysis_destroy_function

```c
void analysis_destroy_function(void);
```

##### Arguments

##### Returns

##### Description

#### analysis_merge_function

```c
void analysis_merge_function(char *a, char *b, char *merged);
```

##### Arguments

##### Returns

##### Description

### Jig API Functions

#### jig_init_function

```c
void jig_init_function(void);
```

##### Arguments

##### Returns

##### Description

#### jig_run_function

```c
char *jig_run_function(u8 *input, size_t input_size, u8 **results, size_t *results_size);
```

##### Arguments

##### Returns

##### Description

#### jig_destroy_function

```c
void jig_destroy_function**(void);
```

##### Arguments

##### Returns

##### Description
