/*
american fuzzy lop - map display utility
----------------------------------------

Written and maintained by Michal Zalewski <lcamtuf@google.com>

Windows fork written by Axel "0vercl0k" Souchet <0vercl0k@tuxfamily.org>

Copyright 2017 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

http://www.apache.org/licenses/LICENSE-2.0

A very simple tool that runs the targeted binary and displays
the contents of the trace bitmap in a human-readable form. Useful in
scripts to eliminate redundant inputs and perform other checks.

Exit code is 2 if the target program crashes; 1 if it times out or
there is a problem executing it; or 0 if execution is successful.

*/
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_RAND_S

#define AFL_MAIN

#include "TinyInst/common.h"
#include "TinyInst/litecov.h"

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"

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

char *target_module;
static s32 child_pid;                 /* PID of the tested program         */

static u8* trace_bits;                /* SHM with instrumentation bitmap   */

static u8 *out_file,                  /* Trace output file                 */
          *doc_path,                  /* Path to docs                      */
          *target_path,               /* Path to target binary             */
          *at_file;                   /* Substitution string for @@        */

static u32 exec_tmout;                /* Exec timeout (ms)                 */

static u64 mem_limit = MEM_LIMIT;     /* Memory limit (MB)                 */

static s32 shm_id;                    /* ID of the SHM region              */

static u8  quiet_mode,                /* Hide non-essential messages?      */
           edges_only,                /* Ignore hit counts?                */
           cmin_mode,                 /* Generate output in afl-cmin mode? */
           binary_mode,               /* Write output as a binary map      */
           keep_cores;                /* Allow coredumps?                  */

static volatile u8
           stop_soon,                 /* Ctrl-C pressed?                   */
           child_timed_out,           /* Child timed out?                  */
           child_crashed;             /* Child crashed?                    */

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


/* Configure shared memory. */

static void setup_shm(void) {

    char* shm_str = NULL;
    u8 attempts = 0;

    trace_bits = ck_alloc(MAP_SIZE);
    if (!trace_bits) PFATAL("shmat() failed");

}

/* Detect @@ in args. */

static void detect_file_args(char** argv) {

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

            // if(at_file[0] != '/') ck_free(aa_subst);

        }

        i++;

    }

    free(cwd); /* not tracked */

}

/* Show banner. */

static void show_banner(void) {

    SAYF("afl-showmap for MacOS " cBRI VERSION cRST " by <linhqttb96@gmail.com>\n");
    SAYF("Based on WinAFL " cBRI WINAFL_VERSION cRST " by <ifratric@google.com>\n");
    SAYF("Based on AFL " cBRI AFL_VERSION cRST " by <lcamtuf@google.com>\n");

}

/* Display usage hints. */

static void usage(u8* argv0) {

    show_banner();

    SAYF("\n%s [ options ] -- \\path\\to\\target_app [ ... ]\n\n"

        "Required parameters:\n\n"

        "  -o file       - file to write the trace data to\n"
        "  -instrument_module module     - target module to test\n\n"

        "Execution control settings:\n\n"

        "  -t msec       - timeout for each run (none)\n"
        "  -m megs       - memory limit for child process (%u MB)\n\n"

        "Other settings:\n\n"

        "  -q            - sink program's output and don't show messages\n"

        "This tool displays raw tuple data captured by AFL instrumentation.\n"
        "For additional help, consult README.\n\n" cRST,

        argv0, MEM_LIMIT);

    exit(1);

}

// run a single iteration over the target process
// whether it's the whole process or target method
// and regardless if the target is persistent or not
// (should know what to do in pretty much all cases)
DebuggerStatus RunTarget(int argc, char **argv, unsigned int pid, uint32_t timeout) {
    DebuggerStatus status;
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

/* Write results. */

static u32 write_results(void) {

    s32 fd;
    FILE* f;
    u32 i, ret = 0;
    u8  cco = !!getenv("AFL_CMIN_CRASHES_ONLY"),
        caa = !!getenv("AFL_CMIN_ALLOW_ANY");

    if (!strncmp(out_file, "/dev/", 5)) {

        fd = open(out_file, O_WRONLY, 0600);
        if (fd < 0) PFATAL("Unable to open '%s'", out_file);

    }
    else if (!strcmp(out_file, "-")) {

        fd = dup(1);
        if (fd < 0) PFATAL("Unable to open stdout");

    }
    else {

        unlink(out_file); /* Ignore errors */
        fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0) PFATAL("Unable to create '%s'", out_file);

    }

    if (binary_mode) {

        for (i = 0; i < MAP_SIZE; i++)
            if (trace_bits[i]) ret++;

        ck_write(fd, trace_bits, MAP_SIZE, out_file);

        close(fd);

    }
    else {

        f = fdopen(fd, "w");

        if (!f) PFATAL("fdopen() failed");

        for (i = 0; i < MAP_SIZE; i++) {

            if (!trace_bits[i]) continue;
            ret++;

            if (cmin_mode) {

                if (child_timed_out) break;
                if (!caa && child_crashed != cco) break;

                fprintf(f, "%u%u\n", trace_bits[i], i);

            }
            else fprintf(f, "%06u:%u\n", i, trace_bits[i]);

        }

        fclose(f);

    }

    return ret;

}

/* Main entry point */

int main(int argc, char** argv) {
    char *optarg;
    u8  mem_limit_given = 0, timeout_given = 0;
    u32 tcnt;
    int i = 0, counter = 0;
    u8 suffix = 0;
    u8 fault;
    int target_argc = 0;
    char **target_argv = NULL;

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

    quiet_mode = GetBinaryOption("-q", argc, argv, false);

    out_file = (u8*)GetOption("-o", argc, argv);
    target_module = GetOption("-instrument_module", argc, argv);

    optarg = GetOption("-t", argc, argv);
    if (optarg) {
        if (sscanf(optarg, "%u%c", &exec_tmout, &suffix) < 1) {
            FATAL("Bad syntax used for -t");
        }
        if (exec_tmout < 5) FATAL("Dangerously low value of -t");
        if (suffix == '+') timeout_given = 2; else timeout_given = 1;
    }
    if (target_opt_ind == 0 || !out_file || !target_module) usage((u8*)argv[0]);

    setup_shm();
    
    fault = RunTarget(target_argc, target_argv, 0, exec_tmout);

    cook_coverage();
    tcnt = write_results();

    if (!quiet_mode) {

        if (!tcnt) SAYF("No instrumentation detected\n");
        OKF("Captured %u tuples in '%s'." cRST, tcnt, out_file);

    }

    exit(fault);
}
