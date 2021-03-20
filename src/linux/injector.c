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
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <unistd.h>
#include <limits.h>
#include "injector_internal.h"

int injector_attach(injector_t **injector_out, pid_t pid)
{
    injector_t *injector;
    int status;
    long retval;
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

    injector->text_size = sysconf(_SC_PAGESIZE);
    injector->stack_size = 2 * 1024 * 1024;

    rv = injector__call_syscall(injector, &retval, injector->sys_mmap, 0,
                                injector->text_size + injector->stack_size, PROT_READ,
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
    injector->text = (size_t)retval;
    injector->stack = injector->text + injector->text_size;
    rv = injector__call_syscall(injector, &retval, injector->sys_mprotect,
                                injector->stack, injector->stack_size,
                                PROT_READ | PROT_WRITE);
    if (rv != 0) {
        goto error_exit;
    }
    if (retval != 0) {
        injector__set_errmsg("mprotect error: %s", strerror(errno));
        rv = INJERR_ERROR_IN_TARGET;
        goto error_exit;
    }
    *injector_out = injector;
    return 0;
error_exit:
    injector_detach(injector);
    return rv;
}

int injector_inject(injector_t *injector, const char *path, void **handle)
{
    char abspath[PATH_MAX];
    size_t len;
    int rv;
    long retval;

    injector__errmsg_is_set = 0;

    if (realpath(path, abspath) == NULL) {
        injector__set_errmsg("failed to get the full path of '%s': %s",
                           path, strerror(errno));
        return INJERR_FILE_NOT_FOUND;
    }
    len = strlen(abspath) + 1;

    if (len > injector->text_size) {
        injector__set_errmsg("too long file path: %s", path);
        return INJERR_FILE_NOT_FOUND;
    }

    rv = injector__write(injector, injector->text, abspath, len);
    if (rv != 0) {
        return rv;
    }
    rv = injector__call_function(injector, &retval, injector->dlopen_addr, injector->text, RTLD_LAZY);
    if (rv != 0) {
        return rv;
    }
    if (retval == 0) {
        injector__set_errmsg("dlopen failed");
        return INJERR_ERROR_IN_TARGET;
    }
    if (handle != NULL) {
        *handle = (void*)retval;
    }
    return 0;
}

int injector_call(injector_t *injector, void *handle, const char* name)
{
    int rv;
    long retval;
    size_t len = strlen(name) + 1;
    if (len > injector->text_size) {
        injector__set_errmsg("too long function name: %s", name);
        return INJERR_FUNCTION_MISSING;
    }
    rv = injector__write(injector, injector->text, name, len);
    if (rv != 0) {
        return rv;
    }
    rv = injector__call_function(injector, &retval, injector->dlsym_addr, handle, injector->text);
    if (retval == 0) {
        injector__set_errmsg("function not found: %s", name);
        return INJERR_FUNCTION_MISSING;
    }
    return injector__call_function(injector, &retval, retval);
}

int injector_uninject(injector_t *injector, void *handle)
{
    int rv;
    long retval;

    injector__errmsg_is_set = 0;

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
        injector__call_syscall(injector, NULL, injector->sys_munmap, injector->text, injector->text_size + injector->stack_size);
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
