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
#include "injector_internal.h"

#if defined(__aarch64__) || defined(__riscv)
#define USE_REGSET
#include <elf.h> /* for NT_PRSTATUS */
#include <sys/uio.h> /* for struct iovec */
#endif

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
    if (ptrace(request, pid, addr, data) != 0) {
        return set_ptrace_error(request_name);
    }
    return 0;
}

int injector__attach_process(const injector_t *injector)
{
    PTRACE_OR_RETURN(PTRACE_ATTACH, injector, 0, 0);
    return 0;
}

int injector__detach_process(const injector_t *injector)
{
    PTRACE_OR_RETURN(PTRACE_DETACH, injector, 0, 0);
    return 0;
}

int injector__get_regs(const injector_t *injector, struct user_regs_struct *regs)
{
#ifdef USE_REGSET
    struct iovec iovec = { regs, sizeof(*regs) };
    PTRACE_OR_RETURN(PTRACE_GETREGSET, injector, NT_PRSTATUS, (long)&iovec);
#else
    PTRACE_OR_RETURN(PTRACE_GETREGS, injector, 0, (long)regs);
#endif
    return 0;
}

int injector__set_regs(const injector_t *injector, const struct user_regs_struct *regs)
{
#ifdef USE_REGSET
    struct iovec iovec = { (void*)regs, sizeof(*regs) };
    PTRACE_OR_RETURN(PTRACE_SETREGSET, injector, NT_PRSTATUS, (long)&iovec);
#else
    PTRACE_OR_RETURN(PTRACE_SETREGS, injector, 0, (long)regs);
#endif
    return 0;
}

int injector__read(const injector_t *injector, size_t addr, void *buf, size_t len)
{
    pid_t pid = injector->pid;
    long word;
    char *dest = (char *)buf;

    errno = 0;
    while (len >= sizeof(long)) {
        word = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
        if (word == -1 && errno != 0) {
            return set_ptrace_error("PTRACE_PEEKTEXT");
        }
        *(long*)dest = word;
        addr += sizeof(long);
        dest += sizeof(long);
        len -= sizeof(long);
    }
    if (len != 0) {
        char *src = (char *)&word;
        word = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
        if (word == -1 && errno != 0) {
            return set_ptrace_error("PTRACE_PEEKTEXT");
        }
        while (len--) {
            *(dest++) = *(src++);
        }
    }
    return 0;
}

int injector__write(const injector_t *injector, size_t addr, const void *buf, size_t len)
{
    pid_t pid = injector->pid;
    const char *src = (const char *)buf;

    while (len >= sizeof(long)) {
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, addr, *(long*)src);
        addr += sizeof(long);
        src += sizeof(long);
        len -= sizeof(long);
    }
    if (len != 0) {
        long word = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
        char *dest = (char*)&word;
        if (word == -1 && errno != 0) {
            return set_ptrace_error("PTRACE_PEEKTEXT");
        }
        while (len--) {
            *(dest++) = *(src++);
        }
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, addr, word);
    }
    return 0;
}

int injector__continue(const injector_t *injector)
{
    PTRACE_OR_RETURN(PTRACE_CONT, injector, 0, 0);
    return 0;
}
