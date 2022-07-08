// DISTRIBUTION STATEMENT A. Approved for public release. Distribution is unlimited.
//
// This material is based upon work supported by the Department of the Air Force under Air Force Contract No. FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the Department of the Air Force.
//
// © 2019 Massachusetts Institute of Technology.
//
// Subject to FAR52.227-11 Patent Rights - Ownership by the contractor (May 2014)
//
// The software/firmware is provided to you on an As-Is basis
//
// Delivered to the U.S. Government with Unlimited Rights, as defined in DFARS Part 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed above. Use of this work other than as specifically authorized by the U.S. Government may violate any copyrights that exist in this work.

#include <bits/stdint-uintn.h>
#include <bits/types/clock_t.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <getopt.h>
#include <nmmintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "analysis.h"
#include "common/logger.h"
#include "common/types.h"
#include "jig.h"
#include "ooze.h"

static fuzzing_strategy strategy;
static jig_api          jig;
static analysis_api     analysis;

static void *strategy_lib = NULL;
static void *jig_lib      = NULL;
static void *analysis_lib = NULL;

static FILE* logging_file = NULL;
static char* strategy_name = NULL;

#define MAX_PATH 1024

#ifdef __linux__
#define PLATFORM_EXTENSTION ".so"
#elif _WIN32
#define PLATFORM_EXTENSTION ".dll"
#elif __APPLE__
#define PLATFORM_EXTENSTION ".dylib"
#else
#define PLATFORM_EXTENSTION ""
#endif

#define INTERESTING_DIR "interesting/"
#define COVERAGE_DIR "coverage/"

static inline u32
crc_buffer(u8 *buffer, size_t size)
{
	u32 crc = 1;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
	u64 *buffer_64 = (u64 *)buffer;
#pragma clang diagnostic pop
	for (size_t i = 0; i < size / 8; i++) {
		crc = (u32)_mm_crc32_u64(crc, buffer_64[i]);
	}

	for (size_t i = (size / 8) * 8; i < size; i++) {
		crc = _mm_crc32_u8(crc, buffer[i]);
	}
	return crc;
}

static void *
load_module(char *module_name)
{
	void  *handle    = NULL;
	size_t full_size = strlen(module_name) + strlen(PLATFORM_EXTENSTION) + 1;

	char *full_module_name = malloc(full_size);
	strncpy(full_module_name, module_name, full_size);
	if (strchr(module_name, '.') == NULL) {

		strncat(full_module_name, PLATFORM_EXTENSTION, full_size);
	}

	if (strchr(module_name, '/') != NULL) {
		handle      = dlopen(full_module_name, RTLD_LAZY);
		char *error = dlerror();
		if (error) {
			log_fatal(error);
		}
	} else {
		char *modules[] = {"ooze/", "jig/", "analysis/", NULL};
		for (size_t i = 0; modules[i] != NULL; i++) {

			char *full_path = malloc(MAX_PATH);
			getcwd(full_path, MAX_PATH);
			size_t left = MAX_PATH - strlen(full_path);

			strncat(full_path, "/", left);
			left = MAX_PATH - strlen(full_path);

			strncat(full_path, modules[i], left);
			left = MAX_PATH - strlen(full_path);

			strncat(full_path, full_module_name, left);

			handle      = dlopen(full_path, RTLD_LAZY);
			char *error = dlerror();
			free(full_path);
			if (error) {
				continue;
			}
			break;
		}
	}

	if (handle == NULL) {
		log_fatal("Couldn't open module: %s", module_name);
	}

	free(full_module_name);
	return handle;
}

// initialize analysis module
static int
initialize_analysis(char *analysis_library_name, char *analysis_load_file)
{

	analysis_lib                 = load_module(analysis_library_name);
	analysis_api_getter *get_api = dlsym(analysis_lib, "get_analysis_api");
	char                *error   = dlerror();
	if (error) {
		log_fatal(error);
	}
	(*get_api)(&analysis);
	analysis.initialize(analysis_load_file);
	return 0;
}

// initialize ooze strategy
static int
initialize_ooze(char *ooze_library_name)
{
	strategy_lib                                            = load_module(ooze_library_name);
	get_fuzzing_strategy_function *get_fuzzing_strategy_ptr = dlsym(strategy_lib, "get_fuzzing_strategy");
	char                          *error                    = dlerror();
	if (error) {
		log_fatal(error);
	}
	(*get_fuzzing_strategy_ptr)(&strategy);

	return 0;
}

// initialize jig
static int
initialize_jig(char *jig_library_name)
{
	jig_lib                 = load_module(jig_library_name);
	jig_api_getter *get_api = dlsym(jig_lib, "get_jig_api");
	char           *error   = dlerror();
	if (error) {
		log_fatal(error);
	}
	(*get_api)(&jig);
	jig.initialize();
	return 0;
}

_Noreturn static void
usage(const char *arg0)
{
	output("usage: %s [options]\n", arg0);
	output("Required:\n");
	output("\t%-32s %-64s\n", "-S [analysis modules]", "path to a analysis module");
	output("\t%-32s %-64s\n", "-O [ooze modules]", "path to an ooze module");
	output("\t%-32s %-64s\n", "-J [jig modules]", "path to a jig module");
	output("\t%-32s %-64s\n", "-i [input file]", "input file");
	output("\t%-32s %-64s\n", "-n [iteration count]", "number of times to fuzz");
	output("\t%-32s %-64s\n", "-s [PRNG seed]", "seed for ooze's PRNG");
	output("\t%-32s %-64s\n", "-x [max input size]", "maximum size for ooze input (must be >= input file size)");
	output("\t%-32s %-64s\n", "-M [max analysis size]", "maximum size for analysis buffer");
	output("\t%-32s %-64s\n", "-c [analysis save file]", "file used to save analysis buffer");

	output("Optional:\n");
	output("\t%-32s %-64s\n", "-C [analysis load file]", "file used to load analysis buffer");

	output("Options to the modules are passed via enviroment variables\n");
	exit(1);
}

static void
load_input_file(char *input_file_name, u8 **base_input, size_t *base_size, size_t max_size)
{
	int fd = open(input_file_name, O_RDONLY);
	if (fd < 0) {
		log_fatal("Can't open %s.", input_file_name);
	}
	off_t file_size;
	file_size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	if ((size_t)file_size > max_size) {
		log_fatal("File size is greater than max size for %s.", input_file_name);
	}

	u8     *file_buffer = calloc(1, max_size + 8);
	ssize_t read_size   = read(fd, file_buffer, (size_t)file_size);
	if (read_size != file_size) {
		log_fatal("Read %zd bytes instead of %zd.", read_size, file_size);
	}

	*base_input = file_buffer;
	*base_size  = (size_t)file_size;
}

// report coverage results for non-interesting inputs
static void
report_coverage(u8 *input, size_t size, u8 *results, size_t results_size, uint32_t crc)
{
	char *coverage_name = NULL;
	asprintf(&coverage_name, COVERAGE_DIR "%x.input", crc);

	// open coverage file
	int coverage_fd = open(coverage_name, O_CREAT | O_WRONLY, 0777);
	if (coverage_fd < 0) {
		log_fatal("Can't open coverage file: '%s'.", coverage_name);
	}

	// write file
	ssize_t write_val = write(coverage_fd, input, size);
	if (write_val >= 0 && (size_t)write_val != size) {
		log_fatal("Can't write to coverage file: '%s'.", coverage_name);
	}
	free(coverage_name);
	close(coverage_fd);

	char *results_name = NULL;
	asprintf(&results_name, COVERAGE_DIR "%x.results", crc);

	// open results file
	int results_fd = open(results_name, O_CREAT | O_WRONLY, 0777);
	if (results_fd < 0) {
		log_fatal("Can't open results file: '%s'.", results_name);
	}
	// write results file
	write_val = write(results_fd, results, results_size);
	if (write_val >= 0 && (size_t)write_val != results_size) {
		log_fatal("Can't write to results file.");
	}
	close(results_fd);
	free(results_name);
}

// report results that we deem interesting
static void
report_interesting(u8 *input, size_t size, char *reason, u8 *results, size_t results_size, uint32_t crc)
{

	char       *interesting_dir = NULL;
	char       *filename        = NULL;
	struct stat st;

	asprintf(&interesting_dir, INTERESTING_DIR "%s/", reason);

	// check if directory to analysis results in already exists
	if (stat(interesting_dir, &st) != 0) {
		mkdir(interesting_dir, 0777);
	}

	// name of file to hold input
	asprintf(&filename, "%s%x.input", interesting_dir, crc);

	// open file
	int interesting_fd = open(filename, O_CREAT | O_WRONLY, 0777);
	if (interesting_fd < 0) {
		log_fatal("Can't open file to save interesting input: '%s'.", filename);
	}
	// write file
	ssize_t write_val = write(interesting_fd, input, size);
	if (write_val >= 0 && (size_t)write_val != size) {
		log_fatal("Could not write to interesting file: '%s'.", filename);
	}

	free(filename);
	close(interesting_fd);

	// if there are trace results to be had
	if (results_size > 0) {

		char *results_name = NULL;

		asprintf(&results_name, "%s%x.results", interesting_dir, crc);
		// open file
		int results_fd = open(results_name, O_CREAT | O_WRONLY, 0777);
		if (results_fd < 0) {
			log_fatal("Can't open file to save trace results to: '%s'.", results_name);
		}
		// write file
		write_val = write(results_fd, results, results_size);
		if (write_val >= 0 && (size_t)write_val != results_size) {
			log_fatal("Can't write to results file '%s'.", results_name);
		}

		close(results_fd);
		free(results_name);
	}
	free(interesting_dir);
}

// run an execution and report results
static void
run_and_report(u8 *input, size_t size, strategy_state* state)
{
	static u8    *results      = NULL;
	static size_t results_size = 0;
	char         *reason       = NULL;
	uint32_t      crc          = crc_buffer(input, size);

	// log_debug("input crc: %llx", crc);
	//  fuzz the binary, getting trace results, trace results size, and exit reason
	reason = jig.run(input, size, &results, &results_size);

	// log_debug("results_size = %llu", results_size);

	// report interesting inputs
	if (reason != NULL && crc) {
		// log_debug("reporting interesting.");
		report_interesting(input, size, reason, results, results_size, crc);
	}

	if (results_size > 0 && crc) {
		// if not interesting, report coverage at least.
		if (!analysis.add(results, results_size, state)) {
			// log_debug("reporting coverage .");
			report_coverage(input, size, results, results_size, crc);
		}
	}
}

/*
#include <openssl/md5.h>
#pragma clang diagnostic push i
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wunreachable-code"
static void __attribute__((noreturn)) 
write_to_file(strategy_state* state, u8* input) { 
    // if (!strategy_name) return NULL;
    char * ext; 
    char * sub = strrchr(strategy_name, '/'); 
    if (sub) sub = sub + 1; 
    ext = strrchr (sub, '.');
    if (ext) *ext = '\0';

        printf("choosing\n");
    if (strncmp(sub, "afl_arith", strlen("afl_arith")) == 0) { 
        printf("match\n");
        afl_arith_substates * substates = (afl_arith_substates *) state->internal_state;
    } else if (strncmp(sub, "afl_bit_flip", strlen("afl_bit_flip")) == 0) {
        afl_bit_flip_substates * substates = (afl_bit_flip_substates *) state->internal_state;
    } else if (strncmp(sub, "afl_interesting", strlen("afl_interesting")) == 0) { 
        afl_interesting_substates * substates = (afl_interesting_substates *) state->internal_state;
    } else if (strncmp(sub, "afl_dictionary", strlen("afl_dictionary")) == 0) { 
        afl_dictionary_substates * substates = (afl_dictionary_substates *) state->internal_state;
    }


    printf("length: %lu, sub: %s\n", strlen(sub), sub); 
    printf("length: %lu, sub: %s\n", strlen("afl_arith"), "afl_arith"); 
    printf("strategy name: %s, input: %s\n", strategy_name, input); 
    if (state->internal_state) {  
        printf("internal_state");
    } 
    exit(1);
}
*/
    
// fuzz a program.
static void
fuzz(char *input_file_name, size_t max_size, u8 *seed, u64 iteration_count)
{
	clock_t         before          = clock();
	u8             *mutation_buffer = NULL;
	u8             *clean_buffer    = calloc(1, max_size + 8);
	strategy_state *state           = NULL; //strategy.create_state(seed, max_size, 0, 0, 0);
	size_t          size            = 0;
	size_t          clean_size      = 0;
        int     log_count = 0;

	// get input file
	load_input_file(input_file_name, &mutation_buffer, &size, max_size);
        //printf("FUZZ: size: %lu\n", size); 
        state = strategy.create_state(seed, max_size, size, clean_buffer, 0, 0, 0);

	// save original input and original input size
	clean_size = size;
	memcpy(clean_buffer, mutation_buffer, size);

	// perform a fuzz run on the original input.
	printf("OG");
	run_and_report(mutation_buffer, size, state);

	// log_debug("max size: %llu", max_size);
	// log_debug("iteration_count: %llu", iteration_count);
	//  commence the fuzzin y'all
	u64 i = 0;

	for (; i < iteration_count; i++) {

        /*if (log_count % 1000 == 0) 
            printf("log_count: %d\n", log_count); 
        if (log_count >= 10000) 
            exit(1);*/

		// mutate the input with ooze
		size = strategy.mutate(mutation_buffer, size, state);
		// log_debug("iteration: %llu, size: %llu.", i, size);
		//  if the mutating is done
		if (size == 0) {
			break;
		}

                //write_to_file(state, mutation_buffer); 
		run_and_report(mutation_buffer, size, state);
                log_count += 1;

		// update state.
		strategy.update_state(state);

		// reset mutation buffer and size.
		memcpy(mutation_buffer, clean_buffer, clean_size);
		size = clean_size;
	}

	// profiling, get run time.
	clock_t difference = clock() - before;
	log_debug("%llu runs completed in %d ms", i + 1, (difference * 1000) / CLOCKS_PER_SEC);

	strategy.free_state(state);
	free(clean_buffer);
	free(mutation_buffer);
}

int
main(int argc, char *argv[])
{
	int    opt;
	char  *analysis_library_name = NULL;
	char  *analysis_load_file    = NULL;
	char  *analysis_save_file    = NULL;
	char  *ooze_library_name     = NULL;
	char  *jig_library_name      = NULL;
	char  *input_file_name       = NULL;
	u64    iteration_count       = 0;
	size_t max_input_size        = 0;
	u8    *ooze_seed             = NULL;
	init_logging();
	while ((opt = getopt(argc, argv, "S:O:i:n:s:C:c:x:J:")) != -1) {
		switch (opt) {
		case 'S':
			if (optarg == NULL) {
				usage(argv[0]);
			}
			analysis_library_name = strdup(optarg);
			break;
		case 'O':
			if (optarg == NULL) {
				usage(argv[0]);
			}
			ooze_library_name = strdup(optarg);
                        strategy_name = strdup(optarg);
			break;
		case 'J':
			if (optarg == NULL) {
				usage(argv[0]);
			}
			jig_library_name = strdup(optarg);
			break;
		case 'i':
			if (optarg == NULL) {
				usage(argv[0]);
			}
			input_file_name = strdup(optarg);
			break;
		case 'n':
			if (optarg == NULL) {
				usage(argv[0]);
			} else if (strcmp("inf", optarg) == 0) {
				iteration_count = UINT64_MAX;
			} else {
				iteration_count = strtoull(optarg, NULL, 10);
			}
			break;
		case 's':
			if (optarg == NULL) {
				usage(argv[0]);
			}
			// seed is expected to be a 32 byte buffer, no more, no less.
			ooze_seed = calloc(1, 33);
			char *foo = strdup(optarg);
			strncpy((char *)ooze_seed, foo, 32);
			free(foo);
			break;
		case 'x':
			if (optarg == NULL) {
				usage(argv[0]);
			}
			max_input_size = strtoull(optarg, NULL, 10);
			break;
		case 'C':
			if (optarg == NULL) {
				usage(argv[0]);
			}
			analysis_load_file = strdup(optarg);
			break;
		case 'c':
			if (optarg == NULL) {
				usage(argv[0]);
			}
			analysis_save_file = strdup(optarg);
			break;
		}
	}
	// Check the arguments
	if (analysis_library_name == NULL ||
	    ooze_library_name == NULL ||
	    jig_library_name == NULL ||
	    input_file_name == NULL ||
	    iteration_count == 0 ||
	    max_input_size == 0) {

		usage(argv[0]);
	}

	if (initialize_analysis(analysis_library_name, analysis_load_file)) {
		log_fatal("analysis failed to initialize");
	}

	if (initialize_ooze(ooze_library_name)) {
		log_fatal("ooze failed to initialize");
	}

	if (initialize_jig(jig_library_name)) {
		log_fatal("jig failed to initialize");
	}

	struct stat st;
	if (stat(INTERESTING_DIR, &st) != 0) {
		mkdir(INTERESTING_DIR, 0777);
	}

	if (stat(COVERAGE_DIR, &st) != 0) {
		mkdir(COVERAGE_DIR, 0777);
	}

        logging_file = fopen("gtfo_logging", "a"); 
        if (!logging_file) {
           log_fatal("couldn't open logging file for appending");  
        }

	fuzz(input_file_name, max_input_size, ooze_seed, iteration_count);

	if (analysis_save_file) {
		analysis.save(analysis_save_file);
	}

        fclose(logging_file); 
        free(strategy_name);

	free(input_file_name);
	free(ooze_seed);
	free(analysis_load_file);
	free(analysis_save_file);
	free(jig_library_name);
	free(ooze_library_name);
	free(analysis_library_name);
	jig.destroy();
	analysis.destroy();

	dlclose(strategy_lib);
	dlclose(jig_lib);
	dlclose(analysis_lib);
}
