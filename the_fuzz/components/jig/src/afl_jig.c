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

#include <bits/types/struct_timeval.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common/logger.h"
#include "common/types.h"
#include "jig.h"

// These are in common, unclear why this is needed but the compiler is complaining
#define unlikely(x) __builtin_expect(!!(x), 0)

// Global variables
static s32    shm_id          = 0;     // ID of the SHM region
static u8    *trace_bits      = NULL;  // SHM with instrumentation bitmap
static size_t map_size        = 0;     // size of the bitmap
static u64    timeout         = 0;     // timeout before we consider the program hung
static int    child_pid       = -1;    // pid of the child process
static bool   child_timed_out = false; // did the child process timeout
static int    forksrv_pid     = -1;    // pid of the fork server
static int    dev_null_fd     = 0;     // file descriptor for /dev/null
static size_t memory_limit    = 0;     // how much memory the target can use
static int    out_fd          = 0;     // the file descriptor which we write our fuzzed input to
static char  *out_file        = NULL;  // the name of the file we write our fuzzed input to
static s32    fsrv_ctl_fd     = 0;     // Fork server control pipe (write)
static s32    fsrv_st_fd      = 0;     // Fork server status pipe (read)

#define DEFAULT_TIMEOUT 1000       // The default timeout in ms
#define DEFAULT_MEMORY_LIMIT 25    // The default memory limit in MB
#define FORKSRV_FD 198             // The forkserver file descriptor used for control messages
#define EXEC_FAIL_SIG 0xfee1dead   // constant used for the forkserver to signal something is wrong
#define SHM_ENV_VAR "__AFL_SHM_ID" // environment variable used to pass the shared memory between the fuzzer and the fork server
//#define STRINGIFY_INTERNAL(x) #x
#//define STRINGIFY(x) STRINGIFY_INTERNAL(x)
#define FORK_WAIT_MULT 10 // how long we're willing to wait for the forkserver to start
#define MEM_BARRIER() __asm__ volatile("" :: \
	                                   : "memory") // memory barrier to prevent race conditions

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
// lookup used for loop binning
// taken from afl-fuzz.c
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-designator"
static const u8          count_class_lookup8[256] = {
    [0]           = 0,
    [1]           = 1,
    [2]           = 2,
    [3]           = 4,
    [4 ... 7]     = 8,
    [8 ... 15]    = 16,
    [16 ... 31]   = 32,
    [32 ... 127]  = 64,
    [128 ... 255] = 128};
#pragma clang diagnostic pop
// lookup used for loop binning
// taken from afl-fuzz.c
static u16 count_class_lookup16[65536];

// initialize lookups used for loop binning
// taken from afl-fuzz.c
static void
init_count_class16(void)
{
	u32 b1, b2;
	for (b1 = 0; b1 < 256; b1++) {
		for (b2 = 0; b2 < 256; b2++) {
			count_class_lookup16[(b1 << 8) + b2] = (u16)((count_class_lookup8[b1] << 8) | count_class_lookup8[b2]);
		}
	}
}

// takes a bitmap from the forkserver and performs loop binning
// taken from afl-fuzz.c
#pragma clang diagnostic ignored "-Wmissing-noreturn"
static inline void
classify_counts(u64 *mem)
{
	printf("CLASSIFY COUNTS:\n");
	u32 i = (u32)map_size >> 3;
	u32 iter;
	for (iter = 0; iter < i; iter++) {
		printf("%lu\n", mem[iter]);
	}
	while (i--) {
		/* Optimize for sparse bitmaps. */
		if (unlikely(*mem)) {
			u16 *mem16 = (u16 *)mem;
			mem16[0]   = count_class_lookup16[mem16[0]];
			mem16[1]   = count_class_lookup16[mem16[1]];
			mem16[2]   = count_class_lookup16[mem16[2]];
			mem16[3]   = count_class_lookup16[mem16[3]];
		}
		mem++;
	}
}

// setup the forkserver that runs the target
// taken from afl-fuzz.c
static void
init_forkserver(char *target, char *target_argv[])
{
	int st_pipe[2], ctl_pipe[2];
	int status;
	s32 rlen;

	if (pipe(st_pipe) || pipe(ctl_pipe)) {
		log_fatal("pipe() failed");
	}

	forksrv_pid = fork();

	if (forksrv_pid < 0) {
		log_fatal("fork() failed");
	}
	if (!forksrv_pid) {
		struct rlimit r;

		/* Umpf. On OpenBSD, the default fd limit for root users is set to soft 128. Let's try to fix that... */
		if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {
			r.rlim_cur = FORKSRV_FD + 2;
			setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */
		}

		if (memory_limit) {
			r.rlim_max = r.rlim_cur = ((rlim_t)memory_limit) << 20;
			setrlimit(RLIMIT_AS, &r); /* Ignore errors */
		}
		/* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered before the dump is complete. */
		r.rlim_max = r.rlim_cur = 0;
		setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

		/* Isolate the process and configure standard descriptors. If out_file is specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */
		setsid();
		dup2(dev_null_fd, 1);
		dup2(dev_null_fd, 2);

		if (out_file) {
			dup2(dev_null_fd, 0);
		} else {
			dup2(out_fd, 0);
			close(out_fd);
		}

		/* Set up control and status pipes, close the unneeded original fds. */

		if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) {
			log_fatal("dup2() failed");
		}
		if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) {
			log_fatal("dup2() failed");
		}
		//fsrv_ctl_fd = ctl_pipe[1];
		//fsrv_st_fd  = st_pipe[0];

		close(ctl_pipe[0]);
		close(ctl_pipe[1]);
		close(st_pipe[0]);
		close(st_pipe[1]);

		// close(out_dir_fd);
		close(dev_null_fd);
		// close(dev_urandom_fd);
		// close(fileno(plot_file));

		/* This should improve performance a bit, since it stops the linker from doing extra work post-fork(). */

		if (!getenv("LD_BIND_LAZY")) {
			setenv("LD_BIND_NOW", "1", 0);
		}

		/* Set sane defaults for ASAN if nothing else specified. */
		//setenv("ASAN_OPTIONS", "abort_on_error=1:detect_leaks=0:symbolize=0allocator_may_return_null=1", 0);

		/* MSAN is tricky, because it doesn't support abort_on_error=1 at this point. So, we do this in a very hacky way. */
		//setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":symbolize=0:abort_on_error=1:allocator_may_return_null=1:msan_track_origins=0", 0);
		// execv(target, NULL);
		int exec_err = execv(target, target_argv);
		if (exec_err != 0) {
			log_fatal(strerror(errno));
		}
		/* Use a distinctive bitmap signature to tell the parent about execv() falling through. */
		*(u32 *)trace_bits = EXEC_FAIL_SIG;
		exit(0);
	}
	/* Close the unneeded endpoints. */
	close(ctl_pipe[0]);
	close(st_pipe[1]);

	fsrv_ctl_fd = ctl_pipe[1];
	fsrv_st_fd  = st_pipe[0];

	/* Wait for the fork server to come up, but don't wait too long. */
	struct itimerval it;
	it.it_value.tv_sec  = ((timeout * FORK_WAIT_MULT) / 1000);
	it.it_value.tv_usec = ((timeout * FORK_WAIT_MULT) % 1000) * 1000;

	setitimer(ITIMER_REAL, &it, NULL);

	rlen = (s32)read(fsrv_st_fd, &status, 4);

	it.it_value.tv_sec  = 0;
	it.it_value.tv_usec = 0;

	setitimer(ITIMER_REAL, &it, NULL);

	/* If we have a four-byte "hello" message from the server, we're all set. Otherwise, try to figure out what went wrong. */

	if (rlen == 4) {
		log_debug("All right - fork server is up.");
		return;
	}

	if (child_timed_out) {
		log_fatal("Timeout while initializing fork server");
	}

	if (waitpid(forksrv_pid, &status, 0) <= 0) {
		log_fatal("waitpid() failed");
	}

	if (WIFSIGNALED(status)) {
		log_fatal("Whoops, the target binary crashed suddenly, before receiving any input from the fuzzer! Fork server crashed with signal %d", WTERMSIG(status));
	}

	if (*(u32 *)trace_bits == EXEC_FAIL_SIG) {
		log_fatal("Unable to execute target application");
	}

	log_fatal("Fork server handshake failed");
}

/* UNUSED FUNCTION
// what to do if the timeout is reached
// taken from afl-fuzz.c
static void
handle_timeout()
{
        if (child_pid > 0) {
                child_timed_out = true;
                kill(child_pid, SIGKILL);

        } else if (child_pid == -1 && forksrv_pid > 0) {
                child_timed_out = true;
                kill(forksrv_pid, SIGKILL);
        }
}
*/
/* Write modified data to file for testing. If out_file is set, the old file is unlinked and a new one is created. Otherwise, out_fd is rewound and truncated. */
// taken from afl-fuzz.c
static void
write_to_testcase(void *input, size_t input_size)
{
	int fd = out_fd;
	if (out_file) {
		unlink(out_file); /* Ignore errors. */
		fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);
		if (fd < 0) {
			log_fatal("Unable to create '%s'", out_file);
		}
	} else {
		lseek(fd, 0, SEEK_SET);
	}
	ssize_t bytes_written = write(fd, input, input_size);
	if (bytes_written > 0 && (size_t)bytes_written != input_size) {
		log_fatal("write failed");
	}
	if (!out_file) {
		if (ftruncate(fd, (off_t)input_size)) {
			log_fatal("ftruncate() failed");
		}
		lseek(fd, 0, SEEK_SET);
	} else
		close(fd);
}

// signals the forkserver to run the target
// most of the code is taken and modified from run_target function in afl-fuzz.c
static char *
fork_run()
{
	static struct itimerval it;
	static u32              prev_timed_out = 0;
	memset(trace_bits, 0, map_size);
	MEM_BARRIER();

	if (write(fsrv_ctl_fd, &prev_timed_out, 4) != 4) {
		log_fatal("Unable to request new process from fork server (OOM?)");
	}

	if (read(fsrv_st_fd, &child_pid, 4) != 4) {
		log_fatal("Unable to request new process from fork server (OOM?)");
	}

	if (child_pid <= 0) {
		log_fatal("Fork server is misbehaving (OOM?)");
	}

	/* Configure timeout, as requested by user, then wait for child to terminate. */
	it.it_value.tv_sec  = (timeout / 1000);
	it.it_value.tv_usec = (timeout % 1000) * 1000;

	setitimer(ITIMER_REAL, &it, NULL);

	int status = 0;
	/* The SIGALRM handler simply kills the child_pid and sets child_timed_out. */
	if (read(fsrv_st_fd, &status, 4) != 4) {
		log_fatal("Unable to communicate with fork server (OOM?)");
	}

	if (!WIFSTOPPED(status)) {
		child_pid = 0;
	}

	it.it_value.tv_sec  = 0;
	it.it_value.tv_usec = 0;

	setitimer(ITIMER_REAL, &it, NULL);

	/* Any subsequent operations on trace_bits must not be moved by the compiler below this point. Past this location, trace_bits[] behave very normally and do not have to be treated as volatile. */
	MEM_BARRIER();

	classify_counts((u64 *)trace_bits);

	prev_timed_out = child_timed_out;

	/* Report outcome to caller. */
	if (WIFSIGNALED(status)) {
		int kill_signal = WTERMSIG(status);
		if (child_timed_out && kill_signal == SIGKILL) {
			return "timeout";
		}
		return "crash";
	}
	return NULL;
}

// initalize the jig
static void
init()
{
	init_logging();
	char *env_map_size = getenv("JIG_MAP_SIZE");
	if (env_map_size == NULL) {
		log_fatal("Missing JIG_MAP_SIZE environment variable.");
	}
	map_size = strtoull(env_map_size, NULL, 0);

	if (errno != 0) {
		log_fatal(strerror(errno));
	}

	char *env_timeout = getenv("JIG_TIMEOUT");
	if (env_timeout == NULL) {
		timeout = DEFAULT_TIMEOUT;
	} else {
		timeout = strtoul(env_timeout, NULL, 0);
		if (errno != 0) {
			log_fatal(strerror(errno));
		}
	}

	char *env_memory_limit = getenv("JIG_MEMORY_LIMIT");
	if (env_memory_limit == NULL) {
		memory_limit = DEFAULT_MEMORY_LIMIT;
	} else {
		memory_limit = strtoul(env_memory_limit, NULL, 0);
		if (errno != 0) {
			log_fatal(strerror(errno));
		}
	}

	char *env_target = getenv("JIG_TARGET");
	if (env_target == NULL) {
		log_fatal("Missing JIG_TARGET environment variable.");
	}
	char       *target = env_target;
	struct stat file_stat;
	if (!(stat(target, &file_stat) == 0 && file_stat.st_mode & S_IXUSR)) {
		log_fatal("Target not executable.");
	} else {
		log_debug("Target is executable.");
	}

	char *env_target_argv = getenv("JIG_TARGET_ARGV");
	if (env_target_argv == NULL) {
		log_fatal("Missing JIG_TARGET_ARGV environment variable.");
	}
	// Only supporting 20 arguments
	char  *target_argv[20] = {0};
	char **target_argv_ptr;

	target_argv[0] = target;

	// very simple argument parsing that doesn't support quotes
	for (target_argv_ptr = &target_argv[1]; (*target_argv_ptr = strsep(&env_target_argv, " \t")) != NULL;) {
		if (**target_argv_ptr != '\0') {
			if (++target_argv_ptr >= &target_argv[20]) {
				break;
			}
		}
	}

	char *fuzzfile = getenv("JIG_FUZZFILE");
	if (fuzzfile == NULL) {
		fuzzfile = "fuzzfile";
	} else {
		out_file = fuzzfile;
	}
	unlink(fuzzfile);
	out_fd = open(fuzzfile, O_RDWR | O_CREAT | O_EXCL, 0600);
	if (out_fd < 0) {
		log_fatal("Creating the fuzzfile failed");
	}

	// Create a new shared memory region
	shm_id = shmget(IPC_PRIVATE, map_size, IPC_CREAT | IPC_EXCL | 0600);
	if (shm_id < 0) {
		log_fatal("shmget() failed");
	}

	// Setup environment variable
	char shm_str[40];
	memset(shm_str, 0, sizeof(shm_str));
	snprintf(shm_str, sizeof(shm_str) - 1, "%d", shm_id);
	setenv(SHM_ENV_VAR, shm_str, 1);

	// Save a pointer to the region in trace_bits
	trace_bits = shmat(shm_id, NULL, 0);
	if (!trace_bits) {
		log_fatal("shmat() failed");
	}
	init_count_class16();

	dev_null_fd = open("/dev/null", O_RDWR);
	if (dev_null_fd < 0) {
		log_fatal("Unable to open /dev/null");
	}

	init_forkserver(target, target_argv);
}

// run an input and collect instrumentation
static char *
run(u8 *input, size_t input_size, u8 **results, size_t *results_size)
{
	write_to_testcase(input, input_size);
	char *status  = fork_run();
	*results_size = map_size;
	*results      = trace_bits;
	return status;
}

// cleanup
static void
destroy()
{
	trace_bits = NULL;
	shmctl(shm_id, IPC_RMID, NULL);
}

static void
create_api(jig_api *j)
{
	j->version     = VERSION_ONE;
	j->name        = "afl_forkserver";
	j->description = "This is a jig for the AFL forkserver";
	j->initialize  = init;
	j->run         = run;
	j->destroy     = destroy;
}

jig_api_getter           get_jig_api = create_api;
#pragma clang diagnostic pop
