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
#include <elf.h>
#include "injector_internal.h"

#ifdef __x86_64__
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

#ifdef __arm__
#ifdef __thumb__
/* BREAKINST_THUMB in linux-source-tree/arch/arm/kernel/ptrace.c */
#define BREAKINST 0xde01
#else
/* BREAKINST_ARM in linux-source-tree/arch/arm/kernel/ptrace.c */
#define BREAKINST 0xe7f001f0
#endif
#endif

#ifdef __aarch64__
#define BREAKINST 0xd4200000 /* asm("brk #0") */
#endif

static int kick_then_wait_sigtrap(const injector_t *injector, struct user_regs_struct *regs, code_t *code, size_t code_size);

/*
 * Call the specified system call in the target process.
 *
 * The arguments after syscall_number must be integer types and
 * the size must not be greater than the size of long.
 */
int injector__call_syscall(const injector_t *injector, long *retval, long syscall_number, ...)
{
    struct user_regs_struct regs = injector->regs;
    code_t code;
    size_t code_size;
    long arg1, arg2, arg3, arg4, arg5, arg6;
    va_list ap;
#if defined(__LP64__) || defined(__x86_64__)
    unsigned long long *reg_return;
#elif defined(__i386__)
    long *reg_return;
#else
    unsigned long *reg_return;
#endif

    va_start(ap, syscall_number);
    arg1 = va_arg(ap, long);
    arg2 = va_arg(ap, long);
    arg3 = va_arg(ap, long);
    arg4 = va_arg(ap, long);
    arg5 = va_arg(ap, long);
    arg6 = va_arg(ap, long);
    va_end(ap);

    switch (injector->e_machine) {
#if defined(__x86_64__)
    case EM_X86_64:
        /* setup instructions */
        code.u8[0] = 0x0f;
        code.u8[1] = 0x05; /* 0f 05 : syscall */
        code.u8[2] = 0xcc; /* cc    : int3    */
        memset(&code.u8[3], 0x90, sizeof(long) - 3); /* fill the rests with `nop` */
        code_size = sizeof(long);
        /* setup registers */
        regs.rip = injector->code_addr;
        regs.rax = syscall_number;
        regs.rdi = arg1;
        regs.rsi = arg2;
        regs.rdx = arg3;
        regs.r10 = arg4;
        regs.r8 = arg5;
        regs.r9 = arg6;
        reg_return = &regs.rax;
        break;
#endif
    default:
#if defined(__x86_64__) || defined(__i386__)
        /* setup instructions */
        code.u8[0] = 0xcd;
        code.u8[1] = 0x80; /* cd 80 : int $80 */
        code.u8[2] = 0xcc; /* cc    : int3    */
        memset(&code.u8[3], 0x90, sizeof(long) - 3); /* fill the rests with `nop` */
        code_size = sizeof(long);
        /* setup registers */
        regs.eip = injector->code_addr;
        regs.eax = syscall_number;
        regs.ebx = arg1;
        regs.ecx = arg2;
        regs.edx = arg3;
        regs.esi = arg4;
        regs.edi = arg5;
        regs.ebp = arg6;
        reg_return = &regs.eax;
#endif
#if defined(__arm__)
        /* setup instructions */
#ifdef __thumb__
        code.u16[0] = 0xdf00; /* svc #0 */
        code.u16[1] = BREAKINST;
        code_size = 2 * 2;
#else
        code.u32[0] = 0xef000000; /* svc #0 */
        code.u32[1] = BREAKINST;
        code_size = 2 * 4;
#endif
        /* setup registers */
#ifdef __thumb__
        regs.uregs[16] |= 1u << 5;
#endif
        regs.uregs[15] = injector->code_addr;
        regs.uregs[7] = syscall_number;
        regs.uregs[0] = arg1;
        regs.uregs[1] = arg2;
        regs.uregs[2] = arg3;
        regs.uregs[3] = arg4;
        regs.uregs[4] = arg5;
        regs.uregs[5] = arg6;
        reg_return = &regs.uregs[0];
#endif
#if defined(__aarch64__)
        /* setup instructions */
        code.u32[0] = 0xd4000001; /* svc #0 */
        code.u32[1] = BREAKINST;
        code_size = 2 * 4;
        /* setup registers */
        regs.pc = injector->code_addr;
        regs.regs[8] = syscall_number;
        regs.regs[0] = arg1;
        regs.regs[1] = arg2;
        regs.regs[2] = arg3;
        regs.regs[3] = arg4;
        regs.regs[4] = arg5;
        regs.regs[5] = arg6;
        reg_return = &regs.regs[0];
#endif
    }

    if (kick_then_wait_sigtrap(injector, &regs, &code, code_size) != 0) {
        return -1;
    }

    if (retval != NULL) {
        if ((unsigned long)*reg_return <= -4096ul) {
            *retval = (long)*reg_return;
        } else {
            errno = -((long)*reg_return);
            *retval = -1;
        }
    }
    return 0;
}

/*
 * Call the function at the specified address in the target process.
 *
 * The arguments after function_addr must be integer types and
 * the size must not be greater than the size of long.
 */
int injector__call_function(const injector_t *injector, long *retval, long function_addr, ...)
{
    struct user_regs_struct regs = injector->regs;
    code_t code;
    size_t code_size;
    long arg1, arg2, arg3, arg4, arg5, arg6;
    va_list ap;
#if defined(__LP64__) || defined(__x86_64__)
    unsigned long long *reg_return;
#elif defined(__i386__)
    long *reg_return;
#else
    unsigned long *reg_return;
#endif

    va_start(ap, function_addr);
    arg1 = va_arg(ap, long);
    arg2 = va_arg(ap, long);
    arg3 = va_arg(ap, long);
    arg4 = va_arg(ap, long);
    arg5 = va_arg(ap, long);
    arg6 = va_arg(ap, long);
    va_end(ap);

    switch (injector->e_machine) {
#if defined(__x86_64__) /* x86_64 target process */
    case EM_X86_64:
        /* setup instructions */
        code.u8[0] = 0xff;
        code.u8[1] = 0xd0; /* ff d0 : callq *%rax */
        code.u8[2] = 0xcc; /* cc    : int3        */
        memset(&code.u8[3], 0x90, sizeof(long) - 3); /* fill the rests with `nop` */
        code_size = sizeof(long);
        /* setup registers */
        regs.rip = injector->code_addr;
        regs.rbp = injector->stack + injector->stack_size - 16;
        /* rsp should be at 16-byte boundary after call instruction.*/
        regs.rsp = injector->stack + injector->stack_size - (2 * 16) + 8;
        regs.rax = function_addr;
        regs.rdi = arg1;
        regs.rsi = arg2;
        regs.rdx = arg3;
        regs.rcx = arg4;
        regs.r8 = arg5;
        regs.r9 = arg6;
        reg_return = &regs.rax;
        break;
#endif
    default:
#if defined(__x86_64__) || defined(__i386__) /* i386 target process */
        /* setup instructions */
        code.u8[0] = 0xff;
        code.u8[1] = 0xd0; /* ff d0 : call *%eax */
        code.u8[2] = 0xcc; /* cc    : int3       */
        memset(&code.u8[3], 0x90, sizeof(long) - 3); /* fill the rests with `nop` */
        code_size = sizeof(long);
        /* setup registers */
        regs.eip = injector->code_addr;
        regs.ebp = injector->stack + injector->stack_size - 16;
        /* esp should be at 16-byte boundary after call instruction.*/
        regs.esp = injector->stack + injector->stack_size - (3 * 16) + 4;
        regs.eax = function_addr;
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.esp + 0, arg1);
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.esp + 4, arg2);
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.esp + 8, arg3);
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.esp + 12, arg4);
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.esp + 16, arg5);
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.esp + 20, arg6);
        reg_return = &regs.eax;
#endif
#if defined(__arm__)
        /* setup instructions */
#ifdef __thumb__
        code.u16[0] = 0x47a0; /* blx r4 */
        code.u16[1] = BREAKINST;
        code_size = 2 * 2;
#else
        code.u32[0] = 0xe12fff34; /* blx r4 */
        code.u32[1] = BREAKINST;
        code_size = 2 * 4;
#endif
        /* setup registers */
#ifdef __thumb__
        regs.uregs[16] |= 1u << 5;
#endif
        regs.uregs[15] = injector->code_addr;
        regs.uregs[13] = injector->stack + injector->stack_size - 16;
        regs.uregs[4] = function_addr;
        regs.uregs[0] = arg1;
        regs.uregs[1] = arg2;
        regs.uregs[2] = arg3;
        regs.uregs[3] = arg4;
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.uregs[13] + 0, arg5);
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.uregs[13] + 4, arg6);
        reg_return = &regs.uregs[0];
#endif
#if defined(__aarch64__)
        /* setup instructions */
        code.u32[0] = 0xd63f00c0; /* blr x6 */
        code.u32[1] = BREAKINST;
        code_size = 2 * 4;
        /* setup registers */
        regs.pc = injector->code_addr;
        regs.sp = injector->stack + injector->stack_size - 16;
        regs.regs[6] = function_addr;
        regs.regs[0] = arg1;
        regs.regs[1] = arg2;
        regs.regs[2] = arg3;
        regs.regs[3] = arg4;
        regs.regs[4] = arg5;
        regs.regs[5] = arg6;
        reg_return = &regs.regs[0];
#endif
    }

    if (kick_then_wait_sigtrap(injector, &regs, &code, code_size) != 0) {
        return -1;
    }

    if (retval != NULL) {
        *retval = (long)*reg_return;
    }
    return 0;
}

static int kick_then_wait_sigtrap(const injector_t *injector, struct user_regs_struct *regs, code_t *code, size_t code_size)
{
    int status;
    int rv = -1;

    if (injector__set_regs(injector, regs) != 0) {
        return -1;
    }
    if (injector__write(injector, injector->code_addr, code, code_size) != 0) {
        injector__set_regs(injector, &injector->regs);
        return -1;
    }

    if (ptrace(PTRACE_CONT, injector->pid, 0, 0) != 0) {
        injector__set_errmsg("PTRACE_CONT error : %s (%s:%d)", strerror(errno), __FILE__, __LINE__);
        goto cleanup;
    }
    while (1) {
        pid_t pid = waitpid(injector->pid, &status, 0);
        if (pid == -1) {
            if (errno == EINTR) {
                continue;
            }
            injector__set_errmsg("waitpid error: %s", strerror(errno));
            goto cleanup;
        }
        if (WIFSTOPPED(status)) {
            switch (WSTOPSIG(status)) {
            case SIGTRAP:
                goto got_sigtrap;
            case SIGSTOP:
                if (ptrace(PTRACE_CONT, injector->pid, 0, 0) != 0) {
                    injector__set_errmsg("PTRACE_CONT error : %s (%s:%d)", strerror(errno), __FILE__, __LINE__);
                    goto cleanup;
                }
                break;
            default:
                injector__set_errmsg("The target process unexpectedly stopped by signal %d.", WSTOPSIG(status));
                goto cleanup;
            }
        } else if (WIFEXITED(status)) {
            injector__set_errmsg("The target process unexpectedly terminated with exit code %d.", WEXITSTATUS(status));
            goto cleanup;
        } else if (WIFSIGNALED(status)) {
            injector__set_errmsg("The target process unexpectedly terminated by signal %d.", WTERMSIG(status));
            goto cleanup;
        } else {
            /* never reach here */
            injector__set_errmsg("Unexpected waitpid status: 0x%x", status);
            goto cleanup;
        }
    }
got_sigtrap:
    if (injector__get_regs(injector, regs) != 0) {
        goto cleanup;
    }
    /* success */
    rv = 0;
cleanup:
    injector__set_regs(injector, &injector->regs);
    injector__write(injector, injector->code_addr, &injector->backup_code, code_size);
    return rv;
}
