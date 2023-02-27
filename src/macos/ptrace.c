/* -*- indent-tabs-mode: nil -*-
 *
 * injector - Library for injecting a shared library into a Linux process
 *
 * URL: https://github.com/kubo/injector
 *
 * ------------------------------------------------------
 *
 * Copyright (C) 2022 TheOiseth
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
#include "injector_internal.h"
#include <libproc.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#define PTRACE_OR_RETURN(request, injector, addr, data) do { \
    int rv = injector__ptrace(request, injector->pid, addr, data, #request); \
    if (rv != 0) { \
        return rv; \
    } \
} while (0)
static int set_ptrace_error(const char *request_name)
{
    int err = errno;
    injector__set_errmsg("%s error : %s", request_name, strerror(errno));
    switch (err) {
    case EFAULT:
        return INJERR_INVALID_MEMORY_AREA;
    case EPERM:
        return INJERR_PERMISSION;
    case ESRCH:
        return INJERR_NO_PROCESS;
    }
    return INJERR_OTHER;
}

int injector__ptrace(int request, pid_t pid, long addr, long data, const char *request_name)
{
    if (ptrace(request, pid, (caddr_t)addr, data) != 0) {
        return set_ptrace_error(request_name);
    }
    return 0;
}

int injector__ptrace_attach(const injector_t *injector)
{
    PTRACE_OR_RETURN(PT_ATTACHEXC, injector, 0, 0);
    return 0;
}

int injector__ptrace_detach(const injector_t *injector)
{
    PTRACE_OR_RETURN(PT_DETACH, injector, 0, 0);
    return 0;
}

int injector__ptrace_continue(const injector_t *injector)
{
    PTRACE_OR_RETURN(PT_CONTINUE, injector, 1, 0);
    return 0;
}

int injector__ptrace_update(const injector_t *injector, long thread_port)
{
    PTRACE_OR_RETURN(PT_THUPDATE, injector, thread_port, 0);
    return 0;
}