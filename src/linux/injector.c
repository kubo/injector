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
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <alloca.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include "injector_internal.h"

static inline size_t remote_mem_size(injector_t *injector) {
    return 2 * injector->data_size + injector->stack_size;
}

int injector_attach(injector_t **injector_out, pid_t pid)
{
    injector_t *injector;
    int status;
    intptr_t retval;
    int prot;
    int rv = 0;

    injector__errmsg_is_set = 0;

    injector = calloc(1, sizeof(injector_t));
    if (injector == NULL) {
        injector__set_errmsg("malloc error: %s", strerror(errno));
        return INJERR_NO_MEMORY;
    }
    injector->pid = pid;
    rv = injector__attach_process(injector);
    if (rv != 0) {
        goto error_exit;
    }
    injector->attached = 1;

    do {
        rv = waitpid(pid, &status, 0);
    } while (rv == -1 && errno == EINTR);
    if (rv == -1) {
        injector__set_errmsg("waitpid error while attaching: %s", strerror(errno));
        rv = INJERR_WAIT_TRACEE;
        goto error_exit;
    }

    rv = injector__collect_libc_information(injector);
    if (rv != 0) {
        goto error_exit;
    }
    rv = injector__get_regs(injector, &injector->regs);
    if (rv != 0) {
        goto error_exit;
    }
    rv = injector__read(injector, injector->code_addr, &injector->backup_code, sizeof(injector->backup_code));
    if (rv != 0) {
        goto error_exit;
    }

    injector->data_size = sysconf(_SC_PAGESIZE);
    injector->stack_size = 2 * 1024 * 1024;

    rv = injector__call_syscall(injector, &retval, injector->sys_mmap, 0,
                                remote_mem_size(injector), PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
    if (rv != 0) {
        goto error_exit;
    }
    if (retval == -1) {
        injector__set_errmsg("mmap error: %s", strerror(errno));
        rv = INJERR_ERROR_IN_TARGET;
        goto error_exit;
    }
    injector->mmapped = 1;
    injector->data = (size_t)retval;
    injector->stack = (size_t)retval + 2 * injector->data_size;
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    injector->shellcode = (size_t)retval + 1 * injector->data_size;
    prot = PROT_READ | PROT_EXEC;
#else
    prot = PROT_NONE;
#endif
    rv = injector__call_syscall(injector, &retval, injector->sys_mprotect,
                                injector->data + injector->data_size, injector->data_size,
                                prot);
    if (rv != 0) {
        goto error_exit;
    }
    if (retval != 0) {
        injector__set_errmsg("mprotect error: %s", strerror(errno));
        rv = INJERR_ERROR_IN_TARGET;
        goto error_exit;
    }
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    rv = injector__write(injector, injector->shellcode, &injector_shellcode, injector_shellcode_size);
    if (rv != 0) {
        return rv;
    }
#endif

    *injector_out = injector;
    return 0;
error_exit:
    injector_detach(injector);
    return rv;
}

int injector_inject(injector_t *injector, const char *path, void **handle)
{
    char abspath[PATH_MAX];
    int dlflags = RTLD_LAZY;
    size_t len;
    int rv;
    intptr_t retval;

    injector__errmsg_is_set = 0;

    if (path[0] == '/') {
        len = strlen(path) + 1;
    } else if (realpath(path, abspath) != NULL) {
        path = abspath;
        len = strlen(abspath) + 1;
    } else {
        injector__set_errmsg("failed to get the full path of '%s': %s",
                           path, strerror(errno));
        return INJERR_FILE_NOT_FOUND;
    }

    if (len > injector->data_size) {
        injector__set_errmsg("too long file path: %s", path);
        return INJERR_FILE_NOT_FOUND;
    }

    rv = injector__write(injector, injector->data, path, len);
    if (rv != 0) {
        return rv;
    }
    if (injector->dlfunc_type == DLFUNC_INTERNAL) {
#define __RTLD_DLOPEN	0x80000000 // glibc internal flag
        dlflags |= __RTLD_DLOPEN;
    }
    rv = injector__call_function(injector, &retval, injector->dlopen_addr, injector->data, dlflags);
    if (rv != 0) {
        return rv;
    }
    if (retval == 0) {
        char buf[256 + 1] = {0,};
        if (injector->dlerror_addr != 0) {
            rv = injector__call_function(injector, &retval, injector->dlerror_addr);
            if (rv == 0 && retval != 0) {
                injector__read(injector, retval, buf, sizeof(buf) - 1);
            }
        }
        if (buf[0] != '\0') {
            injector__set_errmsg("dlopen failed: %s", buf);
        } else {
            injector__set_errmsg("dlopen failed");
        }
        return INJERR_ERROR_IN_TARGET;
    }
    if (handle != NULL) {
        *handle = (void*)retval;
    }
    return 0;
}

#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
int injector_inject_in_cloned_thread(injector_t *injector, const char *path, void **handle_out)
{
    void *data;
    injector_shellcode_arg_t *arg;
    const size_t file_path_offset = offsetof(injector_shellcode_arg_t, file_path);
    void * const invalid_handle = (void*)-3;
    char abspath[PATH_MAX];
    size_t pathlen;
    int rv;
    intptr_t retval;

    injector__errmsg_is_set = 0;

    if (injector->arch != ARCH_X86_64) {
        injector__set_errmsg("injector_inject_in_cloned_thread doesn't support %s.",
                             injector__arch2name(injector->arch));
        return INJERR_UNSUPPORTED_TARGET;
    }

    if (realpath(path, abspath) == NULL) {
        injector__set_errmsg("failed to get the full path of '%s': %s",
                           path, strerror(errno));
        return INJERR_FILE_NOT_FOUND;
    }
    pathlen = strlen(abspath) + 1;

    if (file_path_offset + pathlen > injector->data_size) {
        injector__set_errmsg("too long path name: %s", path);
        return INJERR_FILE_NOT_FOUND;
    }

    data = alloca(injector->data_size);
    memset(data, 0, injector->data_size);
    arg = (injector_shellcode_arg_t *)data;

    arg->handle = invalid_handle;
    arg->dlopen_addr = injector->dlopen_addr;
    arg->dlerror_addr = injector->dlerror_addr;
    arg->dlflags = RTLD_LAZY;
    if (injector->dlfunc_type == DLFUNC_INTERNAL) {
        arg->dlflags |= __RTLD_DLOPEN;
    }
    memcpy(arg->file_path, abspath, pathlen);

    rv = injector__write(injector, injector->data, data, injector->data_size);
    if (rv != 0) {
        return rv;
    }
    rv = injector__call_function(injector, &retval, injector->clone_addr,
                                 injector->shellcode, injector->stack + injector->stack_size - 4096,
                                 //CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID,
                                 CLONE_VM,
                                 injector->data);
    if (rv != 0) {
        return rv;
    }
    if (retval == -1) {
        injector__set_errmsg("clone error: %s", strerror(errno));
        return INJERR_ERROR_IN_TARGET;
    }
    const struct timespec ts = {0, 100000000}; /* 0.1 second */
    void *handle;
    int cnt = 0;

retry:
    nanosleep(&ts, NULL);
    rv = injector__read(injector, injector->data, &handle, sizeof(handle));
    if (rv != 0) {
        return rv;
    }
    if (handle == invalid_handle) {
        int max_retyr_cnt = 50;
        if (++cnt <= max_retyr_cnt) {
            goto retry;
        }
        injector__set_errmsg("dlopen doesn't return in %d seconds.", max_retyr_cnt / 10);
        return INJERR_ERROR_IN_TARGET;
    }
    if (handle_out != NULL) {
        *handle_out = handle;
    }
    if (handle == NULL) {
        arg->file_path[0] = '\0';
        injector__read(injector, injector->data, data, injector->data_size);
        if (arg->file_path[0] != '\0') {
            injector__set_errmsg("%s", arg->file_path);
        } else {
            injector__set_errmsg("dlopen error");
        }
        return INJERR_ERROR_IN_TARGET;
    }
    return 0;
}
#endif

int injector_remote_func_addr(injector_t *injector, void *handle, const char* name, size_t *func_addr_out)
{
    int rv;
    intptr_t retval;
    size_t len = strlen(name) + 1;

    injector__errmsg_is_set = 0;

    if (len > injector->data_size) {
        injector__set_errmsg("too long function name: %s", name);
        return INJERR_FUNCTION_MISSING;
    }
    rv = injector__write(injector, injector->data, name, len);
    if (rv != 0) {
        return rv;
    }
    rv = injector__call_function(injector, &retval, injector->dlsym_addr, handle, injector->data);
    if (rv != 0) {
        return rv;
    }
    if (retval == 0) {
        injector__set_errmsg("function not found: %s", name);
        return INJERR_FUNCTION_MISSING;
    }
    *func_addr_out = (size_t)retval;
    return 0;
}

int injector_remote_call(injector_t *injector, intptr_t *retval, size_t func_addr, ...)
{
    va_list ap;
    int rv;
    injector__errmsg_is_set = 0;
    va_start(ap, func_addr);
    rv = injector__call_function_va_list(injector, retval, func_addr, ap);
    va_end(ap);
    return rv;
}

int injector_remote_vcall(injector_t *injector, intptr_t *retval, size_t func_addr, va_list ap)
{
    injector__errmsg_is_set = 0;
    return injector__call_function_va_list(injector, retval, func_addr, ap);
}

int injector_call(injector_t *injector, void *handle, const char* name)
{
    size_t func_addr;
    int rv = injector_remote_func_addr(injector, handle, name, &func_addr);
    if (rv != 0) {
        return rv;
    }
    return injector__call_function(injector, NULL, func_addr);
}

int injector_uninject(injector_t *injector, void *handle)
{
    int rv;
    intptr_t retval;

    injector__errmsg_is_set = 0;
    if (injector->libc_type == LIBC_TYPE_MUSL) {
        /* Assume that libc is musl. */
        injector__set_errmsg("Cannot uninject libraries under musl libc. See: https://wiki.musl-libc.org/functional-differences-from-glibc.html#Unloading_libraries");
        return INJERR_UNSUPPORTED_TARGET;
    }

    rv = injector__call_function(injector, &retval, injector->dlclose_addr, handle);
    if (rv != 0) {
        return rv;
    }
    if (retval != 0) {
        injector__set_errmsg("dlclose failed");
        return INJERR_ERROR_IN_TARGET;
    }
    return 0;
}

int injector_detach(injector_t *injector)
{
    injector__errmsg_is_set = 0;

    if (injector->mmapped) {
        injector__call_syscall(injector, NULL, injector->sys_munmap, injector->data, remote_mem_size(injector));
    }
    if (injector->attached) {
        injector__detach_process(injector);
    }
    free(injector);
    return 0;
}

const char *injector_error(void)
{
    return injector__errmsg;
}
