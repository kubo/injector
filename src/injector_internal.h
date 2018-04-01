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
#ifndef INJECTOR_INTERNAL_H
#define INJECTOR_INTERNAL_H 1
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <errno.h>
#include "../include/injector.h"

#ifdef __LP64__
#define SIZE_T_FMT "l"
#else
#define SIZE_T_FMT ""
#endif

#ifdef __x86_64__
typedef uint8_t inst_t;
#define TRAMPOLINE_SYSCALL_OFFSET 0
#define TRAMPOLINE_FUNCTION_OFFSET 4
#define TRAMPOLINE_CODE_SIZE 8
#define SYS32_mmap2 192
#define SYS32_mprotect 125
#define SYS32_munmap 91
#define eip rip
#define ebp rbp
#define esp rsp
#define eax rax
#define ebx rbx
#define ecx rcx
#define edx rdx
#define esi rsi
#define edi rdi
#define ebp rbp
#endif

#ifdef __i386__
typedef uint8_t inst_t;
#define TRAMPOLINE_SYSCALL_OFFSET 0
#define TRAMPOLINE_FUNCTION_OFFSET 4
#define TRAMPOLINE_CODE_SIZE 8
#endif

#ifdef __arm__
#define user_regs_struct user_regs
#ifdef __thumb__
/* arm-linux-gnueabihf */
typedef uint16_t inst_t;
#else
/* arm-linux-gnueabi */
typedef uint32_t inst_t;
#endif
#define TRAMPOLINE_SYSCALL_OFFSET 0
#define TRAMPOLINE_FUNCTION_OFFSET (2 * sizeof(inst_t))
#define TRAMPOLINE_CODE_SIZE 4
#endif

#ifdef __aarch64__
typedef uint32_t inst_t;
#define TRAMPOLINE_SYSCALL_OFFSET 0
#define TRAMPOLINE_FUNCTION_OFFSET (2 * sizeof(inst_t))
#define TRAMPOLINE_CODE_SIZE 4
#endif

#define PTRACE_OR_RETURN(request, injector, addr, data) do { \
    if (ptrace(request, injector->pid, addr, data) != 0) { \
        injector__set_errmsg(#request " error : %s (%s:%d)", strerror(errno), __FILE__, __LINE__); \
        return -1; \
    } \
} while (0)

struct injector {
    pid_t pid;
    uint8_t attached;
    uint8_t mmapped;
    uint8_t code_modified;
    uint8_t regs_modified;
    uint16_t e_machine;
    struct user_regs_struct regs;
    size_t dlopen_addr;
    size_t trampoline_addr;
    inst_t backup_code[TRAMPOLINE_CODE_SIZE];
    long sys_mmap;
    long sys_mprotect;
    long sys_munmap;
    size_t text; /* read only region */
    size_t text_size;
    size_t stack; /* stack area */
    size_t stack_size;
};

/* arch.c */
int injector__setup_trampoline_code(const injector_t *injector, inst_t *trampoline_code);
int injector__call_syscall(const injector_t *injector, long *retval, long syscall_number, ...);
int injector__call_function(const injector_t *injector, long *retval, long function_addr, ...);

/* elf.c */
int injector__collect_libc_information(injector_t *injector);

/* ptrace.c */
int injector__attach_process(const injector_t *injector);
int injector__detach_process(const injector_t *injector);
int injector__get_regs(const injector_t *injector, struct user_regs_struct *regs);
int injector__set_regs(const injector_t *injector, const struct user_regs_struct *regs);
int injector__read(const injector_t *injector, size_t addr, void *buf, size_t len);
int injector__write(const injector_t *injector, size_t addr, const void *buf, size_t len);
int injector__run_code(const injector_t *injector, struct user_regs_struct *regs);

/* util.c */
extern char injector__errmsg[];
extern char injector__errmsg_is_set;
void injector__set_errmsg(const char *format, ...);
#endif
