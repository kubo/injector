/* -*- indent-tabs-mode: nil -*-
 *
 * injector - Library for injecting a shared library into a Linux process
 *
 * URL: https://github.com/kubo/injector
 *
 * ------------------------------------------------------
 *
 * Copyright (C) 2018-2023 Kubo Takehiro <kubo@jiubao.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <inttypes.h>
#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#else
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <limits.h>
#endif
#include "../include/injector.h"

#define INCR_ON_INJECTION 13
#define INCR_ON_UNINJECTION 17

#ifdef _WIN32
#define EXEEXT ".exe"
#define DLLEXT ".dll"
static BOOL is_under_wine() {
  static enum {
    ST_UNKNOWN,
    ST_WINE,
    ST_NOT_WINE,
  } state = ST_UNKNOWN;
  if (state == ST_UNKNOWN) {
    if (GetProcAddress(GetModuleHandleA("ntdll.dll"), "wine_get_version")) {
      state = ST_WINE;
    } else {
      state = ST_NOT_WINE;
    }
  }
  return state == ST_WINE;
}

static const char *inject_errmsg()
{
  if (is_under_wine()) {
    return "LoadLibrary in the target process failed: Module not found.";
  } else {
    return "LoadLibrary in the target process failed: The specified module could not be found.";
  }
}
#define INJECT_ERRMSG inject_errmsg()

static const char *uninject_errmsg()
{
  if (is_under_wine()) {
    return "FreeLibrary in the target process failed: Invalid handle.";
  } else {
    return "FreeLibrary in the target process failed: The specified module could not be found.";
  }
}
#define UNINJECT_ERRMSG uninject_errmsg()

#elif __APPLE__
#define EXEEXT ""
#define DLLEXT ".dylib"
#define INJECT_ERRMSG "failed to get the full path of 'no such library': No such file or directory"
#else
#define EXEEXT ""
#define DLLEXT ".so"
#define INJECT_ERRMSG "failed to get the full path of 'no such library': No such file or directory"
#endif

typedef struct process process_t;

static int process_start(process_t *proc, char *test_target);
static int process_check_module(process_t *proc, const char *module_name, int startswith);
static int process_wait(process_t *proc, int wait_secs);
static void process_terminate(process_t *proc);

#ifdef _WIN32

#define sleep(secs) Sleep(1000 * (secs))

struct process {
    DWORD pid;
    HANDLE hProcess;
};

static int process_start(process_t *proc, char *test_target)
{
    STARTUPINFOA si = {sizeof(STARTUPINFOA),};
    PROCESS_INFORMATION pi;

    if (!CreateProcessA(NULL, test_target, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("ERROR: failed to create process: %s\n", test_target);
        return 1;
    }
    CloseHandle(pi.hThread);
    proc->pid = pi.dwProcessId;
    proc->hProcess = pi.hProcess;
    return 0;
}

static int process_check_module(process_t *proc, const char *module_name, int startswith)
{
    HANDLE hSnapshot;
    MODULEENTRY32 me;
    BOOL ok;
    int len = strlen(module_name);

    do {
        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, proc->pid);
    } while (hSnapshot == INVALID_HANDLE_VALUE && GetLastError() == ERROR_BAD_LENGTH);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot error: %d\n", GetLastError());
        return -1;
    }
    me.dwSize = sizeof(me);
    ok = Module32First(hSnapshot, &me);
    while (ok) {
        if ((startswith ? memicmp(me.szModule, module_name, len) : stricmp(me.szModule, module_name)) == 0) {
            CloseHandle(hSnapshot);
            return 0;
        }
        ok = Module32Next(hSnapshot, &me);
    }
    CloseHandle(hSnapshot);
    return 1;
}

static int process_wait(process_t *proc, int wait_secs)
{
    DWORD code;
    int rv = 1;

    code = WaitForSingleObject(proc->hProcess, wait_secs * 1000);
    switch (code) {
    case WAIT_OBJECT_0:
        GetExitCodeProcess(proc->hProcess, &code);
        switch (code) {
        case INCR_ON_INJECTION + INCR_ON_UNINJECTION:
            printf("SUCCESS: The injected library changed the exit_value variable in the target process!\n");
            rv = 0;
            break;
        case INCR_ON_INJECTION:
            printf("ERROR: The library was injected but not uninjected.\n");
            break;
        case 0:
            printf("ERROR: The injected library didn't change the return value of target process!\n");
            break;
        default:
            printf("ERROR: The target process exited with exit code %d.\n", code);
            break;
        }
        break;
    case WAIT_TIMEOUT:
        printf("ERROR: The target process didn't exit.\n");
        break;
    defualt:
        printf("ERROR: WaitForSingleObject\n");
        break;
    }
    return rv;
}

static void process_terminate(process_t *proc)
{
    TerminateProcess(proc->hProcess, 256);
    CloseHandle(proc->hProcess);
}

#else

struct process {
    pid_t pid;
    int waited;
#ifndef __APPLE__
    int is_musl;
#endif
};

static int process_start(process_t *proc, char *test_target)
{
    proc->pid = fork();
    proc->waited = 0;
    if (proc->pid == 0) {
        execl(test_target, test_target, NULL);
        exit(2);
    }
    return 0;
}

#ifdef __APPLE__

static int process_check_module(process_t *proc, const char *module_name, int startswith)
{
    char buf[PATH_MAX];
    size_t len = strlen(module_name);
    FILE *fp;

    sprintf(buf, "vmmap -w %i", proc->pid);
    fp = popen(buf, "r");
    if (fp == NULL) {
        printf("Could not open pipe %s\n", buf);
        return -1;
    }
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        char *p = strrchr(buf, '/');
		if(p == NULL){
			continue;
		}
        if (p != NULL && memcmp(p + 1, module_name, len) == 0 && (startswith || p[len + 1] == '\n')) {
            pclose(fp);
            return 0;
        }
    }
    pclose(fp);
    return 1;
}

static int process_wait(process_t *proc, int wait_secs)
{
    int status;
	long start_sec = time(0);
	pid_t pid = proc->pid;
	do{
		if(time(0)-start_sec>wait_secs){
			break;
		}
		if ((pid = waitpid(pid, &status, WNOHANG)) == -1)
		{
			printf("wait() error\n");
		} else if(pid != 0){
			if (WIFEXITED(status)) {
				int exitcode = WEXITSTATUS(status);
				if (exitcode == INCR_ON_INJECTION + INCR_ON_UNINJECTION) {
					printf("SUCCESS: The injected library changed the exit_value variable in the target process!\n");
					return 0;
				} else if (exitcode == INCR_ON_INJECTION) {
					printf("ERROR: The library was injected but not uninjected.\n");
					return 1;
				} else if (exitcode == 0) {
					printf("ERROR: The injected library didn't change the return value of target process!\n");
					return 1;
				} else {
					printf("ERROR: The target process exited with exit code %d.\n", exitcode);
					return 1;
				}
			} else if (WIFEXITED(status)) {
				int signo = WTERMSIG(status);
				printf("ERROR: The target process exited by signal %d.\n", signo);
				return 1;
			} else if (WIFSTOPPED(status)) {
				int signo = WSTOPSIG(status);
				printf("ERROR: The target process stopped by signal %d.\n", signo);
				return 1;
			} else {
				printf("ERROR: Unexpected waitpid status: 0x%x\n", status);
				return 1;
			}
		 }
	} while (pid == 0);
    printf("ERROR: The target process didn't exit.\n");
    return 1;
}

#else //linux
static volatile sig_atomic_t caught_sigalarm;

static void sighandler(int signo)
{
    caught_sigalarm = 1;
}
static int process_check_module(process_t *proc, const char *module_name, int startswith)
{
    char buf[PATH_MAX];
    size_t len = strlen(module_name);
    FILE *fp;

    sprintf(buf, "/proc/%d/maps", proc->pid);
    fp = fopen(buf, "r");
    if (fp == NULL) {
        printf("Could not open %s\n", buf);
        return -1;
    }
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        char *p = strrchr(buf, '/');
        if (p != NULL && memcmp(p + 1, module_name, len) == 0 && (startswith || p[len + 1] == '\n')) {
            fclose(fp);
            return 0;
        }
    }
    fclose(fp);
    return 1;
}

static int process_wait(process_t *proc, int wait_secs)
{
    struct sigaction sigact;
    int status;

    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = sighandler;
    sigaction(SIGALRM, &sigact, NULL);
    alarm(wait_secs);

    if (waitpid(proc->pid, &status, 0) == proc->pid) {
        proc->waited = 1;
        if (WIFEXITED(status)) {
            int exitcode = WEXITSTATUS(status);
            if (exitcode == INCR_ON_INJECTION + INCR_ON_UNINJECTION) {
                if (proc->is_musl) {
                    printf("ERROR: the library was uninjected, which shouldn't be possible on musl.\n");
                    return 0;
                } else {
                    printf("SUCCESS: The injected library changed the exit_value variable in the target process!\n");
                    return 0;
                }
            } else if (exitcode == INCR_ON_INJECTION) {
                if (proc->is_musl) {
                    printf("SUCCESS: The injected library changed the exit_value variable in the target process!\n");
                    return 0;
                } else {
                    printf("ERROR: The library was injected but not uninjected.\n");
                    return 1;
                }
            } else if (exitcode == 0) {
                printf("ERROR: The injected library didn't change the return value of target process!\n");
                return 1;
            } else {
                printf("ERROR: The target process exited with exit code %d.\n", exitcode);
                return 1;
            }
        } else if (WIFEXITED(status)) {
            int signo = WTERMSIG(status);
            printf("ERROR: The target process exited by signal %d.\n", signo);
            return 1;
        } else if (WIFSTOPPED(status)) {
            int signo = WSTOPSIG(status);
            printf("ERROR: The target process stopped by signal %d.\n", signo);
            return 1;
        } else {
            printf("ERROR: Unexpected waitpid status: 0x%x\n", status);
            return 1;
        }
    }
    if (caught_sigalarm) {
        printf("ERROR: The target process didn't exit.\n");
    } else {
        printf("ERROR: waitpid failed. (%s)\n", strerror(errno));
    }
    return 1;
}
#endif
static void process_terminate(process_t *proc)
{
    int status;
    if (!proc->waited) {
        kill(proc->pid, SIGKILL);
        kill(proc->pid, SIGCONT);
        waitpid(proc->pid, &status, 0);
    }
}

#endif

static int test_remote_call(injector_t *injector, void *handle)
{
#ifdef INJECTOR_HAS_REMOTE_CALL_FUNCS
    printf("test remote call.\n");
    fflush(stdout);

    size_t func_addr;
    if (injector_remote_func_addr(injector, handle, "sum_integers", &func_addr) != 0) {
        printf("injector_remote_func_addr error:\n  %s\n", injector_error());
        return -1;
    }
    intptr_t retval;
    intptr_t args[6] = {1, 2, 3, 4, 5, 6};
    int i;
    for (i = 0; i < 6; i++) {
        args[i] += 10;
        intptr_t expected_retval = args[0] + args[1] + args[2] + args[3] + args[4] + args[5];
        if (injector_remote_call(injector, &retval, func_addr, args[0], args[1], args[2], args[3], args[4], args[5]) != 0) {
            printf("injector_remote_call error:\n  %s\n", injector_error());
            return -1;
        }
        if (retval != expected_retval) {
            printf("sum_integers(%" PRIdPTR ", %" PRIdPTR ", %" PRIdPTR ", %" PRIdPTR ", %" PRIdPTR ", %" PRIdPTR ") returns %" PRIdPTR " (expected %" PRIdPTR ")\n",
                   args[0], args[1], args[2], args[3], args[4], args[5], retval, expected_retval);
            return -1;
        }
    }
#endif
    return 0;
}

int main(int argc, char **argv)
{
    char suffix[20] = {0,};
    char test_target[64];
    char test_library[64];
    injector_t *injector;
    process_t proc;
    void *handle = NULL;
    int rv = 1;
    int loop_cnt;
    int can_uninject;
    int (*inject_func)(injector_t *, const char *, void **) = injector_inject;
    int i;

    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (strcmp(argv[i], "--cloned-thread") == 0) {
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
                inject_func = injector_inject_in_cloned_thread;
#else
                fprintf(stderr, "injector_inject_in_cloned_thread isn't suported\n");
                return 1;
#endif
            } else {
                fprintf(stderr, "unknown option %s\n", argv[i]);
                return 1;
            }
        } else {
            snprintf(suffix, sizeof(suffix), "-%s", argv[1]);
            suffix[sizeof(suffix) - 1] = '\0';
        }
    }

    snprintf(test_target, sizeof(test_target), "test-target%s" EXEEXT, suffix);
    snprintf(test_library, sizeof(test_library), "test-library%s" DLLEXT, suffix);

    if (process_start(&proc, test_target) != 0) {
        return 1;
    }
    printf("target process started.\n");
    fflush(stdout);

    sleep(1);

#if defined(_WIN32) || defined(__APPLE__)
    can_uninject = 1;
#else
    // Sadly this is not known at compile time, see https://www.openwall.com/lists/musl/2013/03/29/13
    proc.is_musl = process_check_module(&proc, "ld-musl-", 1) == 0;
    // In musl, dlclose doesn't do anything - see https://wiki.musl-libc.org/functional-differences-from-glibc.html
    can_uninject = proc.is_musl ? 0 : 1;
#endif

    for (loop_cnt = 0; loop_cnt < 2; loop_cnt++) {
        const char *errmsg;

        if (injector_attach(&injector, proc.pid) != 0) {
            printf("inject error:\n  %s\n", injector_error());
            goto cleanup;
        }
        printf("attached.\n");
        fflush(stdout);

        if (loop_cnt == 0) {
            if (inject_func(injector, test_library, &handle) != 0) {
                printf("inject error:\n  %s\n", injector_error());
                goto cleanup;
            }
            printf("injected. (handle=%p)\n", handle);
            fflush(stdout);

            if (inject_func(injector, "no such library", &handle) == 0) {
                printf("injection should fail but succeeded:\n");
                goto cleanup;
            }
            errmsg = injector_error();
            if (strncmp(errmsg, INJECT_ERRMSG, strlen(INJECT_ERRMSG)) != 0) {
                printf("unexpected injection error message: %s\nexpected: %s\n", errmsg, INJECT_ERRMSG);
                goto cleanup;
            }
            if (test_remote_call(injector, handle) != 0) {
                goto cleanup;
            }
        } else {
            if (injector_uninject(injector, handle) != 0) {
                printf("uninject error:\n  %s\n", injector_error());
                goto cleanup;
            }
            printf("uninjected.\n");
            fflush(stdout);

#ifdef _WIN32
            if (injector_uninject(injector, NULL) == 0) {
                printf("uninjection should fail but succeeded:\n");
                goto cleanup;
            }
            errmsg = injector_error();
            if (strcmp(errmsg, UNINJECT_ERRMSG) != 0) {
                printf("unexpected uninjection error message: %s\nexpected: %s\n", errmsg, UNINJECT_ERRMSG);
                goto cleanup;
            }
#endif
        }

        if (injector_detach(injector) != 0) {
            printf("inject error:\n  %s\n", injector_error());
            goto cleanup;
        }
        printf("detached.\n");
        fflush(stdout);

        if (can_uninject && process_check_module(&proc, test_library, 0) != loop_cnt) {
            if (loop_cnt == 0) {
                printf("%s wasn't found after injection\n", test_library);
            } else {
                printf("%s was found after uninjection\n", test_library);
            }
            goto cleanup;
        }
    }

    rv = process_wait(&proc, 8);
cleanup:
    process_terminate(&proc);
    return rv;
}

