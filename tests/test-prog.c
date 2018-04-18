/* -*- indent-tabs-mode: nil -*-
 *
 * injector - Library for injecting a shared library into a Linux process
 *
 * URL: https://github.com/kubo/injector
 *
 * ------------------------------------------------------
 *
 * Copyright (C) 2018 Kubo Takehiro <kubo@jiubao.org>
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
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../include/injector.h"

static volatile sig_atomic_t caught_sigalarm;

static void sighandler(int signo)
{
    caught_sigalarm = 1;
}

int main(int argc, char **argv)
{
    pid_t pid;
    char suffix[20] = {0,};
    char test_target[64];
    char test_library[64];
    struct sigaction sigact;
    injector_t *injector;
    int status;

    if (argc > 1) {
        snprintf(suffix, sizeof(suffix), "-%s", argv[1]);
        suffix[sizeof(suffix) - 1] = '\0';
    }
    snprintf(test_target, sizeof(test_target), "./test-target%s", suffix);
    snprintf(test_library, sizeof(test_library), "./test-library%s.so", suffix);

    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = sighandler;
    sigaction(SIGALRM, &sigact, NULL);
    alarm(6);

    pid = fork();
    if (pid == 0) {
        execl(test_target, test_target, NULL);
        return 1;
    }
    printf("targe process started.\n");
    fflush(stdout);

    sleep(1);

    if (injector_attach(&injector, pid) != 0) {
        printf("inject error:\n  %s\n", injector_error());
        goto cleanup;
    }
    printf("attached.\n");
    fflush(stdout);

    if (injector_inject(injector, test_library) != 0) {
        printf("inject error:\n  %s\n", injector_error());
        goto cleanup;
    }
    printf("injected.\n");
    fflush(stdout);

    if (injector_detach(injector) != 0) {
        printf("inject error:\n  %s\n", injector_error());
        goto cleanup;
    }
    printf("detached.\n");
    fflush(stdout);

    if (waitpid(pid, &status, 0) == pid) {
        if (WIFEXITED(status)) {
            int exitcode = WEXITSTATUS(status);
            if (exitcode == 123) {
                printf("SUCCESS: The injected library changed the exit_value variable in the targe process!\n");
                return 0;
            } else if (exitcode == 0) {
                printf("ERROR: The injected library didn't change the return value of targe process!\n");
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
cleanup:
    kill(pid, SIGKILL);
    kill(pid, SIGCONT);
    return 1;
}

