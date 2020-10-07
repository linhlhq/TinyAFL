/*
american fuzzy lop - test case minimizer
----------------------------------------

Written and maintained by Michal Zalewski <lcamtuf@google.com>

Copyright 2015, 2016 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

http://www.apache.org/licenses/LICENSE-2.0

A simple test case minimizer that takes an input file and tries to remove
as much data as possible while keeping the binary in a crashing state
*or* producing consistent instrumentation output (the mode is auto-selected
based on the initially observed behavior).

*/

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"
#include "TinyInst/common.h"
#include "TinyInst/litecov.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>

Coverage coverage;
LiteCov *instrumentation;
int num_iterations;
int cur_iteration;
bool persist;
int optind;
char *optarg;
char *target_module;

static u64 watchdog_timeout_time;
static u8 watchdog_enabled;
static s32 prog_in_fd = 0;

static u64 name_seed;              /* Random integer to have a unique shm/pipe name */
static u8 *fuzzer_id = NULL;      /* The fuzzer ID or a randomized
									  seed allowing multiple instances */

static u8 *trace_bits,                /* SHM with instrumentation bitmap   */
		  *mask_bitmap;               /* Mask for trace bits (-B)          */

static u8 *in_file,                   /* Minimizer input test case         */
		  *out_file,                  /* Minimizer output file             */
		  *target_path,               /* Path to target binary             */
		  *at_file,                   /* Substitution string for @@        */
		  *doc_path;                  /* Path to docs                      */

u8 *file_extension;

static u8* in_data;                   /* Input data for trimming           */

static u32 in_len,                    /* Input data length                 */
		   orig_cksum,                /* Original checksum                 */
		   total_execs,               /* Total number of execs             */
		   missed_hangs,              /* Misses due to hangs               */
		   missed_crashes,            /* Misses due to crashes             */
		   missed_paths,              /* Misses due to exec path diffs     */
		   exec_tmout = EXEC_TIMEOUT; /* Exec timeout (ms)                 */

static u64 mem_limit = MEM_LIMIT;     /* Memory limit (MB)                 */

//static s32 shm_id,                    /* ID of the SHM region              */

static u8  crash_mode,                /* Crash-centric mode?               */
		   exit_crash,                /* Treat non-zero exit as crash?     */
		   edges_only,                /* Ignore hit counts?                */
		   use_stdin = 1;             /* Use stdin for program input?      */

static volatile u8
		stop_soon,                 /* Ctrl-C pressed?                   */
		child_timed_out,           /* Child timed out?                  */
		child_crashed;             /* Child crashed?                    */

u32 cpu_core_count;            /* CPU core count                   */
u64 cpu_aff = 0;				/* Selected CPU core                */

/* Classify tuple counts. Instead of mapping to individual bits, as in
afl-fuzz.c, we map to more user-friendly numbers between 1 and 8. */

#define AREP4(_sym)   (_sym), (_sym), (_sym), (_sym)
#define AREP8(_sym)   AREP4(_sym), AREP4(_sym)
#define AREP16(_sym)  AREP8(_sym), AREP8(_sym)
#define AREP32(_sym)  AREP16(_sym), AREP16(_sym)
#define AREP64(_sym)  AREP32(_sym), AREP32(_sym)
#define AREP128(_sym) AREP64(_sym), AREP64(_sym)

static u8 count_class_lookup[256] = {

	/* 0 - 3:       4 */ 0, 1, 2, 3,
	/* 4 - 7:      +4 */ AREP4(4),
	/* 8 - 15:     +8 */ AREP8(5),
	/* 16 - 31:   +16 */ AREP16(6),
	/* 32 - 127:  +96 */ AREP64(7), AREP32(7),
	/* 128+:     +128 */ AREP128(8)

};

static void classify_counts(u8* mem) {

	u32 i = MAP_SIZE;

	if (edges_only) {

		while (i--) {
			if (*mem) *mem = 1;
			mem++;
		}

	}
	else {

		while (i--) {
			*mem = count_class_lookup[*mem];
			mem++;
		}

	}

}


/* Apply mask to classified bitmap (if set). */

static void apply_mask(u32* mem, u32* mask) {

	u32 i = (MAP_SIZE >> 2);

	if (!mask) return;

	while (i--) {

		*mem &= ~*mask;
		mem++;
		mask++;

	}

}


/* See if any bytes are set in the bitmap. */

static inline u8 anything_set(void) {

	u32* ptr = (u32*)trace_bits;
	u32  i = (MAP_SIZE >> 2);

	while (i--) if (*(ptr++)) return 1;

	return 0;

}



// run a single iteration over the target process
// whether it's the whole process or target method
// and regardless if the target is persistent or not
// (should know what to do in pretty much all cases)
DebuggerStatus RunTarget(int argc, char **argv, unsigned int pid, uint32_t timeout) {
	DebuggerStatus status;
	total_execs++;
	// else clear only when the target function is reached
	if (!instrumentation->IsTargetFunctionDefined()) {
		instrumentation->ClearCoverage();
	}

	if (instrumentation->IsTargetAlive() && persist) {
		status = instrumentation->Continue(timeout);
	}
	else {
		instrumentation->Kill();
		cur_iteration = 0;
		if (argc) {
			status = instrumentation->Run(argc, argv, timeout);
		}
		else {
			status = instrumentation->Attach(pid, timeout);
		}
	}

	// if target function is defined,
	// we should wait until it is hit
	if (instrumentation->IsTargetFunctionDefined()) {
		if ((status != DEBUGGER_TARGET_START) && argc) {
			// try again with a clean process
			WARN("Target function not reached, retrying with a clean process\n");
			instrumentation->Kill();
			cur_iteration = 0;
			status = instrumentation->Run(argc, argv, timeout);
		}

		if (status != DEBUGGER_TARGET_START) {
			switch (status) {
			case DEBUGGER_CRASHED:
				FATAL("Process crashed before reaching the target method\n");
				break;
			case DEBUGGER_HANGED:
				FATAL("Process hanged before reaching the target method\n");
				break;
			case DEBUGGER_PROCESS_EXIT:
				FATAL("Process exited before reaching the target method\n");
				break;
			default:
				status = (DebuggerStatus)DEBUGGER_FAULT_ERROR;
				FATAL("An unknown problem occured before reaching the target method\n");
				break;
			}
		}

		instrumentation->ClearCoverage();

		status = instrumentation->Continue(timeout);
	}

	switch (status) {
	case DEBUGGER_CRASHED:
		//printf("Process crashed\n");
		instrumentation->Kill();
		break;
	case DEBUGGER_HANGED:
		//printf("Process hanged\n");
		instrumentation->Kill();
		break;
	case DEBUGGER_PROCESS_EXIT:
		if (instrumentation->IsTargetFunctionDefined()) {
			//printf("Process exit during target function\n");
		}
		else {
			//printf("Process finished normally\n");
		}
		break;
	case DEBUGGER_TARGET_END:
		if (instrumentation->IsTargetFunctionDefined()) {
			//printf("Target function returned normally\n");
			cur_iteration++;
			if (cur_iteration == num_iterations) {
				instrumentation->Kill();
			}
		}
		else {
			FATAL("Unexpected status received from the debugger\n");
		}
		break;
	default:
		status = (DebuggerStatus)DEBUGGER_FAULT_ERROR;
		FATAL("Unexpected status received from the debugger\n");
		break;
	}
	return status;
}


/* Configure shared memory. */

static void setup_shm(void) {

	char* shm_str = NULL;
	u8 attempts = 0;

	trace_bits = ck_alloc(MAP_SIZE);
	if (!trace_bits) PFATAL("shmat() failed");

}

/* Read initial file. */

static void read_initial_file(void) {

	struct stat st;
	s32 fd = open(in_file, O_RDONLY);

	if (fd < 0) PFATAL("Unable to open '%s'", in_file);

	if (fstat(fd, &st) || !st.st_size)
		FATAL("Zero-sized input file.");

	if (st.st_size >= TMIN_MAX_FILE)
		FATAL("Input file is too large (%u MB max)", TMIN_MAX_FILE / 1024 / 1024);

	in_len = st.st_size;
	in_data = ck_alloc_nozero(in_len);

	ck_read(fd, in_data, in_len, in_file);

	close(fd);

	OKF("Read %u byte%s from '%s'.", in_len, in_len == 1 ? "" : "s", in_file);

}

void SafeTerminateProcess() {
	instrumentation->Kill();
	cur_iteration = 0;
}


/* Write output file. */

static s32 write_to_file(u8* path, u8* mem, u32 len) {

    s32 ret;

    unlink(path); /* Ignore errors */

    ret = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);

    if (ret < 0) PFATAL("Unable to create '%s'", path);

    ck_write(ret, mem, len, path);

    lseek(ret, 0, SEEK_SET);

    return ret;

}


void move_coverage(u8* trace, Coverage cov_module)
{
	for (auto iter = cov_module.begin(); iter != cov_module.end(); iter++) {
		for (auto iter1 = iter->offsets.begin(); iter1 != iter->offsets.end(); iter1++) {
			u32 index = *iter1 % MAP_SIZE;
			trace[index] ++;
		}
	}
}

/* My way transform coverage of tinyinst to map coverage*/
void cook_coverage()
{
	memset(trace_bits, 0, MAP_SIZE);
	Coverage newcoverage;
	instrumentation->GetCoverage(newcoverage, true);
	move_coverage(trace_bits, newcoverage);
	classify_counts(trace_bits);
}


/* Execute target application.  Returns 0 if the changes are a dud, or
   1 if they should be kept. */

static u8 run_target(int argc, char** argv, u8* mem, u32 len, u8 first_run) {

	char command[] = "R";
	char result = 0;
	u32 cksum;

	prog_in_fd = write_to_file(at_file, mem, len);

	if (prog_in_fd) {
		close(prog_in_fd);
		prog_in_fd = 0;
	}

	result = RunTarget(argc, argv, 0, exec_tmout);

	child_timed_out = 0;
	cook_coverage();

	apply_mask((u32*)trace_bits, (u32*)mask_bitmap);
	total_execs++;

	child_crashed = result == DEBUGGER_CRASHED;

	/* Handle crashing inputs depending on current mode. */
	if (child_crashed) {
		//SafeTerminateProcess();
		if (first_run) crash_mode = 1;
		if (crash_mode) {
			return 1;
		}
		else {
			missed_crashes++;
			return 0;
		}
	}

	/* Handle non-crashing inputs appropriately. */
	if (crash_mode) {
		missed_paths++;
		return 0;
	}

	cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

	if (first_run) orig_cksum = cksum;

	if (orig_cksum == cksum) return 1;

	missed_paths++;
	return 0;
}

/* Find first power of two greater or equal to val. */

static u32 next_p2(u32 val) {

	u32 ret = 1;
	while (val > ret) ret <<= 1;
	return ret;

}


/* Actually minimize! */

static void minimize(int argc, char** argv) {

	static u32 alpha_map[256];

	u8* tmp_buf = ck_alloc_nozero(in_len);
	u32 orig_len = in_len, stage_o_len;

	u32 del_len, set_len, del_pos, set_pos, i, alpha_size, cur_pass = 0;
	u32 syms_removed, alpha_del0 = 0, alpha_del1, alpha_del2, alpha_d_total = 0;
	u8  changed_any, prev_del;

	/***********************
	* BLOCK NORMALIZATION *
	***********************/

	set_len = next_p2(in_len / TMIN_SET_STEPS);
	set_pos = 0;

	if (set_len < TMIN_SET_MIN_SIZE) set_len = TMIN_SET_MIN_SIZE;

	ACTF(cBRI "Stage #0: " cRST "One-time block normalization...");

	while (set_pos < in_len) {

		u8  res;
		u32 use_len = MIN(set_len, in_len - set_pos);

		for (i = 0; i < use_len; i++)
			if (in_data[set_pos + i] != '0') break;

		if (i != use_len) {

			memcpy(tmp_buf, in_data, in_len);
			memset(tmp_buf + set_pos, '0', use_len);

			res = run_target(argc, argv, tmp_buf, in_len, 0);

			if (res) {

				memset(in_data + set_pos, '0', use_len);
				changed_any = 1;
				alpha_del0 += use_len;

			}

		}

		set_pos += set_len;

	}

	alpha_d_total += alpha_del0;

	OKF("Block normalization complete, %u byte%s replaced.", alpha_del0,
		alpha_del0 == 1 ? "" : "s");

next_pass:

	ACTF(cYEL "--- " cBRI "Pass #%u " cYEL "---", ++cur_pass);
	changed_any = 0;

	/******************
	* BLOCK DELETION *
	******************/

	del_len = next_p2(in_len / TRIM_START_STEPS);
	stage_o_len = in_len;

	ACTF(cBRI "Stage #1: " cRST "Removing blocks of data...");

next_del_blksize:

	if (!del_len) del_len = 1;
	del_pos = 0;
	prev_del = 1;
    
	SAYF(cGRA "    Block length = %u, remaining size = %u\n" cRST,
		del_len, in_len);

	while (del_pos < in_len) {

		u8  res;
		s32 tail_len;

		tail_len = in_len - del_pos - del_len;
		if (tail_len < 0) tail_len = 0;

		/* If we have processed at least one full block (initially, prev_del == 1),
		and we did so without deleting the previous one, and we aren't at the
		very end of the buffer (tail_len > 0), and the current block is the same
		as the previous one... skip this step as a no-op. */

		if (!prev_del && tail_len && !memcmp(in_data + del_pos - del_len,
			in_data + del_pos, del_len)) {

			del_pos += del_len;
			continue;

		}

		prev_del = 0;

		/* Head */
		memcpy(tmp_buf, in_data, del_pos);

		/* Tail */
		memcpy(tmp_buf + del_pos, in_data + del_pos + del_len, tail_len);

		res = run_target(argc, argv, tmp_buf, del_pos + tail_len, 0);

		if (res) {

			memcpy(in_data, tmp_buf, del_pos + tail_len);
			prev_del = 1;
			in_len = del_pos + tail_len;

			changed_any = 1;

		}
		else del_pos += del_len;

	}

	if (del_len > 1 && in_len >= 1) {

		del_len /= 2;
		goto next_del_blksize;

	}

	OKF("Block removal complete, %u bytes deleted.", stage_o_len - in_len);

	if (!in_len && changed_any)
		WARNF(cLRD "Down to zero bytes - check the command line and mem limit!" cRST);

	if (cur_pass > 1 && !changed_any) goto finalize_all;

	/*************************
	* ALPHABET MINIMIZATION *
	*************************/

	alpha_size = 0;
	alpha_del1 = 0;
	syms_removed = 0;

	memset(alpha_map, 0, 256 * sizeof(u32));

	for (i = 0; i < in_len; i++) {
		if (!alpha_map[in_data[i]]) alpha_size++;
		alpha_map[in_data[i]]++;
	}

	ACTF(cBRI "Stage #2: " cRST "Minimizing symbols (%u code point%s)...",
		alpha_size, alpha_size == 1 ? "" : "s");

	for (i = 0; i < 256; i++) {

		u32 r;
		u8 res;

		if (i == '0' || !alpha_map[i]) continue;

		memcpy(tmp_buf, in_data, in_len);

		for (r = 0; r < in_len; r++)
			if (tmp_buf[r] == i) tmp_buf[r] = '0';

		res = run_target(argc, argv, tmp_buf, in_len, 0);

		if (res) {

			memcpy(in_data, tmp_buf, in_len);
			syms_removed++;
			alpha_del1 += alpha_map[i];
			changed_any = 1;

		}

	}

	alpha_d_total += alpha_del1;

	OKF("Symbol minimization finished, %u symbol%s (%u byte%s) replaced.",
		syms_removed, syms_removed == 1 ? "" : "s",
		alpha_del1, alpha_del1 == 1 ? "" : "s");

	/**************************
	* CHARACTER MINIMIZATION *
	**************************/

	alpha_del2 = 0;

	ACTF(cBRI "Stage #3: " cRST "Character minimization...");

	memcpy(tmp_buf, in_data, in_len);

	for (i = 0; i < in_len; i++) {

		u8 res, orig = tmp_buf[i];

		if (orig == '0') continue;
		tmp_buf[i] = '0';

		res = run_target(argc, argv, tmp_buf, in_len, 0);

		if (res) {

			in_data[i] = '0';
			alpha_del2++;
			changed_any = 1;

		}
		else tmp_buf[i] = orig;

	}

	alpha_d_total += alpha_del2;

	OKF("Character minimization done, %u byte%s replaced.",
		alpha_del2, alpha_del2 == 1 ? "" : "s");

	if (changed_any) goto next_pass;

finalize_all:

	SAYF("\n"
		cGRA "     File size reduced by : " cRST "%0.02f%% (to %u byte%s)\n"
		cGRA "    Characters simplified : " cRST "%0.02f%%\n"
		cGRA "     Number of execs done : " cRST "%u\n"
		cGRA "          Fruitless execs : " cRST "path=%u crash=%u hang=%s%u\n\n",
		100 - ((double)in_len) * 100 / orig_len, in_len, in_len == 1 ? "" : "s",
		((double)(alpha_d_total)) * 100 / (in_len ? in_len : 1),
		total_execs, missed_paths, missed_crashes, missed_hangs ? cLRD : "",
		missed_hangs);

	if (total_execs > 50 && missed_hangs * 10 > total_execs)
		WARNF(cLRD "Frequent timeouts - results may be skewed." cRST);

}


/* Do basic preparations - persistent fds, filenames, etc. */

static void set_up_environment(void) {
	if (file_extension) {
		if (!at_file) {
			at_file = alloc_printf("afl-tmin-temp.%s", file_extension);
		}
	}
	else {
		if (!at_file) {
			at_file = alloc_printf("afl-tmin-temp");
		}
	}
}

/* Detect @@ in args. */

static void detect_file_args(int argc, char** argv) {

	u32 i = 0;
	u8* cwd = getcwd(NULL, 0);

	if (!cwd) PFATAL("getcwd() failed");

	while (argv[i]) {

		u8* aa_loc = strstr(argv[i], "@@");

		if (aa_loc) {

			u8 *aa_subst, *n_arg;

			if (!at_file) FATAL("@@ syntax is not supported by this tool.");

			/* Be sure that we're always using fully-qualified paths. */

			aa_subst = at_file;

			/* Construct a replacement argv value. */

			*aa_loc = 0;
			n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
			argv[i] = n_arg;
			*aa_loc = '@';

			use_stdin = 0;
			// if(at_file[0] != '/') ck_free(aa_subst);

		}

		i++;

	}

	free(cwd); /* not tracked */

}


/* Display usage hints. */

static void usage(u8* argv0) {

	SAYF("\n%s [ options ] -- /path/to/target_app [ ... ]\n\n"

		"Required parameters:\n\n"

		"  -i file       - input test case to be shrunk by the tool\n"
		"  -o file       - final output location for the minimized data\n"
		"  -instrument_module module     - target module to test\n\n"

		"Execution control settings:\n\n"

		"  -t msec       - timeout for each run (%u ms)\n"

		"For additional tips, please consult README.\n\n",

		argv0, EXEC_TIMEOUT);

	exit(1);

}

/* Main entry point */

int main(int argc, char** argv) {

	u8  mem_limit_given = 0, timeout_given = 0, qemu_mode = 0;
	char** use_argv;
	u8 suffix = 0;
	optind = 1;
	int target_argc = 0;
	char **target_argv = NULL;
	//setup_watchdog_timer();

	SAYF(cCYA "afl-tmin " cBRI VERSION cRST " for tiny-afl\n");
	SAYF(cCYA "Based on afl-tmin by <lcamtuf@google.com>\n");

	instrumentation = new LiteCov();
	instrumentation->Init(argc, argv);

	int target_opt_ind = 0;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0) {
			target_opt_ind = i + 1;
			break;
		}
	}
	target_argc = (target_opt_ind) ? argc - target_opt_ind : 0;
	target_argv = (target_opt_ind) ? argv + target_opt_ind : NULL;

	in_file = GetOption("-i", argc, argv);
	out_file = GetOption("-o", argc, argv);
	file_extension = GetOption("-e", argc, argv);

	exec_tmout = GetIntOption("-t", argc, argv, EXEC_TIMEOUT);
	timeout_given = 1;
	target_module = GetOption("-instrument_module", argc, argv);
    persist = GetBinaryOption("-persist", argc, argv, true);
    num_iterations = GetIntOption("-iterations", argc, argv, 10000);

	setup_shm();
	set_up_environment();

	detect_file_args(argc - target_opt_ind, argv + target_opt_ind);

	if (target_argv == NULL || !out_file || !in_file || !target_module) usage(argv[0]);

	SAYF("\n");

	read_initial_file();

	ACTF("Performing dry run (mem limit = %llu MB, timeout = %u ms%s)...",
		mem_limit, exec_tmout, edges_only ? ", edges only" : "");

	run_target(target_argc, target_argv, in_data, in_len, 1);

	if (child_timed_out)
		FATAL("Target binary times out (adjusting -t may help).");

	if (!crash_mode) {

		OKF("Program terminates normally, minimizing in "
			cCYA "instrumented" cRST " mode.");

		if (!anything_set()) FATAL("No instrumentation detected.");

	}
	else {

		OKF("Program exits with a signal, minimizing in " cMGN "crash" cRST
			" mode.");

	}

	minimize(target_argc, target_argv);

	ACTF("Writing output to '%s'...", out_file);

	close(write_to_file(out_file, in_data, in_len));

	OKF("We're done here. Have a nice day!\n");

	exit(0);

}

