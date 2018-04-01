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
#include <sys/types.h>
#include <sys/wait.h>
#include "injector_internal.h"

#if defined(__aarch64__)
#define USE_REGSET
#include <sys/uio.h> /* for struct iovec */
#endif

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
    PTRACE_OR_RETURN(PTRACE_GETREGSET, injector, (void*)NT_PRSTATUS, &iovec);
#else
    PTRACE_OR_RETURN(PTRACE_GETREGS, injector, 0, regs);
#endif
    return 0;
}

int injector__set_regs(const injector_t *injector, const struct user_regs_struct *regs)
{
#ifdef USE_REGSET
    struct iovec iovec = { regs, sizeof(*regs) };
    PTRACE_OR_RETURN(PTRACE_SETREGSET, injector, (void*)NT_PRSTATUS, &iovec);
#else
    PTRACE_OR_RETURN(PTRACE_SETREGS, injector, 0, regs);
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
            injector__set_errmsg("PTRACE_PEEKTEXT error: %s", strerror(errno));
            return -1;
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
            injector__set_errmsg("PTRACE_PEEKTEXT error: %s", strerror(errno));
            return -1;
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
            injector__set_errmsg("PTRACE_PEEKTEXT error: %s", strerror(errno));
            return -1;
        }
        while (len--) {
            *(dest++) = *(src++);
        }
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, addr, word);
    }
    return 0;
}

int injector__run_code(const injector_t *injector, struct user_regs_struct *regs)
{
    int status;

    if (injector__set_regs(injector, regs) != 0) {
        return -1;
    }
    PTRACE_OR_RETURN(PTRACE_CONT, injector, 0, 0);
    while (1) {
        pid_t pid = waitpid(injector->pid, &status, 0);
        if (pid == -1) {
            if (errno == EINTR) {
                continue;
            }
            injector__set_errmsg("waitpid error: %s", strerror(errno));
            return -1;
        }
        if (WIFSTOPPED(status)) {
            if (WSTOPSIG(status) == SIGTRAP) {
                break;
            }
            PTRACE_OR_RETURN(PTRACE_CONT, injector, 0, 0);
        } else if (WIFEXITED(status)) {
            injector__set_errmsg("The target process unexpectedly terminated with exit code %d.", WEXITSTATUS(status));
            return -1;
        } else if (WIFSIGNALED(status)) {
            injector__set_errmsg("The target process unexpectedly terminated by signal %d.", WTERMSIG(status));
            return -1;
        } else {
            /* never reach here */
            injector__set_errmsg("Unexpected waitpid status: 0x%x", status);
            return -1;
        }
    }
    if (injector__get_regs(injector, regs) != 0) {
        return -1;
    }
    return 0;
}
