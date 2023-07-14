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
#include <stdlib.h>
#include <string.h>
#include "injector.h"

#ifdef __linux
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <limits.h>

#define INVALID_PID -1
static pid_t find_process(const char *name)
{
    DIR *dir = opendir("/proc");
    struct dirent *dent;
    pid_t pid = -1;

    if (dir == NULL) {
        fprintf(stderr, "Failed to read proc file system.\n");
        exit(1);
    }
    while ((dent = readdir(dir)) != NULL) {
        char path[sizeof(dent->d_name) + 11];
        char exepath[PATH_MAX];
        ssize_t len;
        char *exe;

        if (dent->d_name[0] < '1' || '9' < dent->d_name[0]) {
            continue;
        }
        sprintf(path, "/proc/%s/exe", dent->d_name);
        len = readlink(path, exepath, sizeof(exepath) - 1);
        if (len == -1) {
            continue;
        }
        exepath[len] = '\0';
        exe = strrchr(exepath, '/');
        if (exe != NULL && strcmp(exe + 1, name) == 0) {
            pid = atoi(dent->d_name);
            break;
        }
    }
    closedir(dir);
    return pid;
}
#endif

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include "../util/ya_getopt.h"

#define INVALID_PID 0
static DWORD find_process(const char *name)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD pid = 0;
    size_t namelen = strlen(name);

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);

        if (Process32First(hSnapshot, &pe)) {
            do {
                if (_strnicmp(pe.szExeFile, name, namelen) == 0) {
                    if (pe.szExeFile[namelen] == '\0' || stricmp(pe.szExeFile + namelen, ".exe") == 0) {
                        pid = pe.th32ProcessID;
                        break;
                    }
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return pid;
}

#endif
#ifdef __APPLE__
#define INVALID_PID -1
#import <sys/sysctl.h>
#include "../util/ya_getopt.h"
static pid_t find_process(const char *name)
{
	pid_t pid = -1;
    int max_arg_size = 0;
	size_t size = sizeof(max_arg_size);
	if (sysctl((int[]){ CTL_KERN, KERN_ARGMAX }, 2, &max_arg_size, &size, NULL, 0) != 0) {
		max_arg_size = 4096; 
	}
	
	int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL};
	struct kinfo_proc *processes = NULL;
	char* buffer = NULL;
	size_t length;
	int count;

	if (sysctl(mib, 3, NULL, &length, NULL, 0) < 0){
		goto clean;
	}
	processes = malloc(length);
	if (processes == NULL){
		goto clean;
	}
	if (sysctl(mib, 3, processes, &length, NULL, 0) < 0) {
		goto clean;
	}
	count = length / sizeof(struct kinfo_proc);
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROCARGS2;
	
	buffer = (char *)malloc(max_arg_size);
	for (int i = 0; i < count; i++) {
		pid_t p_pid = processes[i].kp_proc.p_pid;
		if (pid == 0) {
			continue;
		}
		mib[2] = p_pid;
		size = max_arg_size;
		
		if (sysctl(mib, 3, buffer, &size, NULL, 0) == 0) {
			char* exe_path = buffer + sizeof(int);
			char* exe_name = exe_path;
			char* next = 0;
			do{
				next = strchr(exe_name, '/');
				if(next != NULL){
					exe_name = next + 1;
				}
			} while (next != NULL);
			if(strcmp(exe_name, name) == 0){
				pid = p_pid;
				goto clean;
			}
		}
	}
clean:
	if(buffer != 0){
		free(buffer);
	}
	if(processes != 0){
		free(processes);
	}
	
	return pid;
}
#endif
int main(int argc, char **argv)
{
    injector_pid_t pid = INVALID_PID;
    injector_t *injector;
    int opt;
    int i;
    char *endptr;
    int rv = 0;
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    const char *optstring = "n:p:T";
    int cloned_thread = 0;
#else
    const char *optstring = "n:p:";
#endif

    while ((opt = getopt(argc, argv, optstring)) != -1) {
        switch (opt) {
        case 'n':
            pid = find_process(optarg);
            if (pid == INVALID_PID) {
                fprintf(stderr, "could not find the process: %s\n", optarg);
                return 1;
            }
            printf("targeting process \"%s\" with pid %d\n", optarg, pid);
            break;
        case 'p':
            pid = strtol(optarg, &endptr, 10);
            if (pid <= 0 || *endptr != '\0') {
                fprintf(stderr, "invalid process id number: %s\n", optarg);
                return 1;
            }
            printf("targeting process with pid %d\n", pid);
            break;
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
        case 'T':
            cloned_thread = 1;
            break;
#endif
        }
    }
    if (pid == INVALID_PID) {
        fprintf(stderr, "Usage: %s [-n process-name] [-p pid] library-to-inject ...\n", argv[0]);
        return 1;
    }

    if (injector_attach(&injector, pid) != 0) {
        printf("%s\n", injector_error());
        return 1;
    }
    for (i = optind; i < argc; i++) {
        char *libname = argv[i];
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
        if (cloned_thread) {
            if (injector_inject_in_cloned_thread(injector, libname, NULL) == 0) {
                printf("clone thread to inject \"%s\" was created.\n", libname);
            } else {
                fprintf(stderr, "could not create cloned thread \"%s\"\n", libname);
                fprintf(stderr, "  %s\n", injector_error());
                rv = 1;
            }
            continue;
        }
#endif
        if (injector_inject(injector, libname, NULL) == 0) {
            printf("\"%s\" successfully injected\n", libname);
        } else {
            fprintf(stderr, "could not inject \"%s\"\n", libname);
            fprintf(stderr, "  %s\n", injector_error());
            rv = 1;
        }
    }
    injector_detach(injector);
    return rv;
}
