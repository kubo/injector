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
#ifndef INJECTOR_INTERNAL_H
#define INJECTOR_INTERNAL_H 1
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <errno.h>
#include "injector.h"

#ifdef __LP64__
#define SIZE_T_FMT "l"
#else
#define SIZE_T_FMT ""
#endif

#ifdef __arm__
#define user_regs_struct user_regs
#endif

#ifdef __mips__
#include <asm/ptrace.h>
#define user_regs_struct pt_regs
#endif

#ifdef __powerpc__
#include <asm/ptrace.h>
#define user_regs_struct pt_regs
#endif

#ifdef __riscv
#include <asm/ptrace.h>
#endif

#define PTRACE_OR_RETURN(request, injector, addr, data) do { \
    int rv = injector__ptrace(request, injector->pid, addr, data, #request); \
    if (rv != 0) { \
        return rv; \
    } \
} while (0)

typedef enum {
    /* use dlopen/dlsym/dlclose (glibc 2.34 or later) */
    DLFUNC_POSIX,
    /* use __libc_dlopen_mode/__libc_dlsym/__libc_dlclose" (glibc 2.33 or earlier) */
    DLFUNC_INTERNAL,
} dlfunc_type_t;

typedef enum {
    ARCH_X86_64,
    ARCH_X86_64_X32,
    ARCH_I386,
    ARCH_ARM64,
    ARCH_ARM_EABI_THUMB,
    ARCH_ARM_EABI,
    ARCH_MIPS_64,
    ARCH_MIPS_N32,
    ARCH_MIPS_O32,
    ARCH_POWERPC_64,
    ARCH_POWERPC,
    ARCH_RISCV_64,
    ARCH_RISCV_32,
} arch_t;

typedef union {
#if defined(__x86_64__) || defined(__i386__)
    uint8_t u8[sizeof(long)];
#elif defined(__aarch64__) || defined(__arm__)
    uint16_t u16[4];
    uint32_t u32[2];
#elif defined(__mips__)
    uint32_t u32[4];
#elif defined(__powerpc__)
    uint32_t u32[2];
#elif defined(__riscv)
    uint32_t u32[2];
#endif
    long dummy;
} code_t;

struct injector {
    pid_t pid;
    uint8_t attached;
    uint8_t mmapped;
    arch_t arch;
    struct user_regs_struct regs;
    dlfunc_type_t dlfunc_type;
    size_t dlopen_addr;
    size_t dlclose_addr;
    size_t dlsym_addr;
    size_t dlerror_addr;
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    size_t clone_addr;
#endif
    size_t code_addr; /* address where instructions are written */
    code_t backup_code;
    long sys_mmap;
    long sys_mprotect;
    long sys_munmap;

    /* memory layout allocated in the target process
     *
     *  high +----------------------+
     *       |     stack area       |
     *       |      size: 2MB       |
     *       |----------------------|
     *       |  inaccessible area   |
     *       |      size: 4096      |
     *       |----------------------|
     *       |      data area       |
     *       |      size: 4096      |
     *  low  +----------------------+
     */
    size_t data; /* read-write region */
    size_t data_size; /* page size */
    size_t stack; /* stack area */
    size_t stack_size; /* 2MB */
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    size_t shellcode;
#endif
};

/* elf.c */
int injector__collect_libc_information(injector_t *injector);

/* ptrace.c */
int injector__ptrace(int request, pid_t pid, long addr, long data, const char *request_name);
int injector__attach_process(const injector_t *injector);
int injector__detach_process(const injector_t *injector);
int injector__get_regs(const injector_t *injector, struct user_regs_struct *regs);
int injector__set_regs(const injector_t *injector, const struct user_regs_struct *regs);
int injector__read(const injector_t *injector, size_t addr, void *buf, size_t len);
int injector__write(const injector_t *injector, size_t addr, const void *buf, size_t len);
int injector__continue(const injector_t *injector);

/* remote_call.c - call functions and syscalls in the target process */
int injector__call_syscall(const injector_t *injector, intptr_t *retval, long syscall_number, ...);
int injector__call_function(const injector_t *injector, intptr_t *retval, long function_addr, ...);
int injector__call_function_va_list(const injector_t *injector, intptr_t *retval, long function_addr, va_list ap);

/* util.c */
extern char injector__errmsg[];
extern char injector__errmsg_is_set;
void injector__set_errmsg(const char *format, ...) __attribute__((format (printf, 1, 2)));
const char *injector__arch2name(arch_t arch);

/* shellcode.S */
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
typedef struct {
    void *handle;
    size_t dlopen_addr;
    size_t dlerror_addr;
    int dlflags;
    char file_path[0]; // dummy size.
} injector_shellcode_arg_t;

void *injector_shellcode(injector_shellcode_arg_t *arg);
extern int injector_shellcode_size;
#endif

#endif
