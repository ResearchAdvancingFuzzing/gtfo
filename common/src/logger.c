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
#include "common/logger.h"
#include "common/types.h" // for STRINGIFY
#include <stdarg.h>       // for va_list
#include <stdio.h>        // for NULL, fopen, vfprintf, FILE, stdout
#include <stdlib.h>       // for getenv, exit
#include <string.h>       // for strstr

#ifndef MODULE
#define MODULE
#endif

static FILE *log_file      = NULL;
static char *debug_modules = NULL;

static void
log_vraw(char *msg, va_list args)
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
	vfprintf(log_file, msg, args);
#pragma clang diagnostic pop
}

void
output(char *msg, ...)
{
	va_list args;
	va_start(args, msg);
	log_vraw(msg, args);
	va_end(args);
}

void
log_info(char *msg, ...)
{
	output("[+] " STRINGIFY(MODULE) ": ");
	va_list args;
	va_start(args, msg);
	log_vraw(msg, args);
	va_end(args);
	output("\n");
}

void
log_warn(char *msg, ...)
{
	// puts("ANDY [!] " STRINGIFY(MODULE) ": ");
	output("[!] " STRINGIFY(MODULE) ": ");
	va_list args;
	va_start(args, msg);
	log_vraw(msg, args);
	va_end(args);
	output("\n");
}

_Noreturn void
log_fatal(char *msg, ...)
{
	output("[X] " STRINGIFY(MODULE) ": ");
	va_list args;
	va_start(args, msg);
	log_vraw(msg, args);
	va_end(args);
	output("\n");
	exit(1);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
void
log_debug(char *msg, ...)
{
#ifdef DEBUG
	if (strstr(debug_modules, STRINGIFY(MODULE)) != NULL) {
		output("[?] " STRINGIFY(MODULE) ": ");
		va_list args;
		va_start(args, msg);
		log_vraw(msg, args);
		va_end(args);
		output("\n");
	}
#endif
}
#pragma clang diagnostic pop

void
log_report_seed(char *seed)
{
	output("[S] " STRINGIFY(MODULE) ": ");
	output(seed);
	output("\n");
}

void
log_report_crash(char *crash)
{
	output("[C] " STRINGIFY(MODULE) ": ");
	output(crash);
	output("\n");
}

// Nocturne and plugins may call_logging() as well as client (test) software.
// But given that all invocations would either log to the $LOG_FILENAME or stdout,
// there shouldn't be a conflict between these two client classes. If filenames could
// be supplied to this call, then set the policy that Nocturne/plugins cannot supply a filename
// and use whatever is open.
void
init_logging(void)
{
	if (log_file == NULL) {
		char *log_filename = getenv("LOG_FILENAME");
		if (log_filename == NULL) {
			log_file = stdout;
		} else {
			log_file = fopen(log_filename, "wb");
		}
	}

	debug_modules = getenv("LOG_DEBUG_MODULES");
	if (debug_modules == NULL) {
		debug_modules = "";
	}
}
