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
#include <sys/syscall.h>
#include <unistd.h>
#include <limits.h>
#include <elf.h>
#include "injector_internal.h"

static void restore_regs(injector_t *injector)
{
    if (injector->regs_modified) {
        injector__set_regs(injector, &injector->regs);
        injector->regs_modified = 0;
    }
}

injector_t *injector_new(pid_t pid)
{
    injector_t *injector;
    inst_t trampoline_code[TRAMPOLINE_CODE_SIZE];
    int status;
    long retval;

    injector__errmsg_is_set = 0;

    injector = calloc(1, sizeof(injector_t));
    if (injector == NULL) {
        injector__set_errmsg(NULL, "malloc error: %s", strerror(errno));
        return NULL;
    }
    injector->pid = pid;
    if (injector__attach_process(injector) != 0) {
        goto error_exit;
    }
    injector->attached = 1;

    waitpid(pid, &status, 0);

    injector->pid = pid;
    if (injector__collect_libc_information(injector) != 0) {
        goto error_exit;
    }
    if (injector__setup_trampoline_code(injector, trampoline_code) != 0) {
        goto error_exit;
    }
    if (injector__get_regs(injector, &injector->regs) != 0) {
        goto error_exit;
    }
    if (injector__read(injector, injector->trampoline_addr, injector->backup_code, sizeof(injector->backup_code)) != 0) {
        goto error_exit;
    }

    injector->text_size = sysconf(_SC_PAGESIZE);
    injector->stack_size = 2 * 1024 * 1024;

#if defined(__i386__) || defined(__arm__)
    injector->sys_mmap = SYS_mmap2;
#else
    injector->sys_mmap = SYS_mmap;
#endif
    injector->sys_mprotect = SYS_mprotect;
    injector->sys_munmap = SYS_munmap;
#if defined(__x86_64__)
    if (injector->e_machine == EM_386) {
        injector->sys_mmap = SYS32_mmap2;
        injector->sys_mprotect = SYS32_mprotect;
        injector->sys_munmap = SYS32_munmap;
    }
#endif

    injector->code_modified = 1;
    if (injector__write(injector, injector->trampoline_addr, trampoline_code, sizeof(trampoline_code)) != 0) {
        goto error_exit;
    }
    injector->regs_modified = 1;
    if (injector__call_syscall(injector, &retval, injector->sys_mmap, 0,
                             injector->text_size + injector->stack_size, PROT_READ,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0) != 0) {
        goto error_exit;
    }
    if (retval == -1) {
        injector__set_errmsg("mmap error: %s", strerror(errno));
        goto error_exit;
    }
    injector->mmapped = 1;
    injector->text = (size_t)retval;
    injector->stack = injector->text + injector->text_size;
    if (injector__call_syscall(injector, &retval, injector->sys_mprotect, injector->stack, injector->stack_size,
                             PROT_READ | PROT_WRITE) != 0) {
        goto error_exit;
    }
    if (retval != 0) {
        injector__set_errmsg("mprotect error: %s", strerror(errno));
        goto error_exit;
    }
    restore_regs(injector);
    return injector;
error_exit:
    injector_delete(injector);
    return NULL;
}

int injector_inject(injector_t *injector, const char *path)
{
    char abspath[PATH_MAX];
    size_t len;
    long retval;

    injector__errmsg_is_set = 0;

    if (realpath(path, abspath) == NULL) {
        injector__set_errmsg("failed to get the full path of '%s': %s",
                           path, strerror(errno));
        goto error_exit;
    }
    len = strlen(abspath) + 1;

    if (len > injector->text_size) {
        injector__set_errmsg("too long file path");
        goto error_exit;
    }

    if (injector__write(injector, injector->text, abspath, len) != 0) {
        goto error_exit;
    }
    injector->regs_modified = 1;
    if (injector__call_function(injector, &retval, injector->dlopen_addr, injector->text, RTLD_LAZY) != 0) {
        goto error_exit;
    }
    if (retval == 0) {
        injector__set_errmsg("dlopen failed");
        goto error_exit;
    }
    restore_regs(injector);
    return 0;
error_exit:
    restore_regs(injector);
    return -1;
}

int injector_delete(injector_t *injector)
{
    injector__errmsg_is_set = 0;

    if (injector->mmapped) {
        injector->regs_modified = 1;
        injector__call_syscall(injector, NULL, injector->sys_munmap, injector->text, injector->text_size + injector->stack_size);
    }
    if (injector->code_modified) {
        injector__write(injector, injector->trampoline_addr, injector->backup_code, sizeof(injector->backup_code));
    }
    restore_regs(injector);
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
