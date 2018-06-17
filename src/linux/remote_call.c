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

#if defined(__arm__)
#define reg32_return reg_return
#define uregs regs.uregs
#endif

#define THUMB_MODE_BIT (1u << 5)
#define BREAKINST_THUMB 0xde01 /* in linux-source-tree/arch/arm/kernel/ptrace.c */
#define BREAKINST_ARM 0xe7f001f0 /* in linux-source-tree/arch/arm/kernel/ptrace.c */
#define BREAKINST_ARM64 0xd4200000 /* asm("brk #0") */

/* register type used in struct user_regs_struct */
#if defined(__LP64__) || defined(__x86_64__)
typedef unsigned long long user_reg_t;
#elif defined(__i386__)
typedef long user_reg_t;
#else
typedef unsigned long user_reg_t;
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
    int rv;
    user_reg_t *reg_return = NULL;
#if defined(__aarch64__)
    uint32_t *reg32_return = NULL;
    uint32_t *uregs = (uint32_t *)&regs;
#endif

    va_start(ap, syscall_number);
    arg1 = va_arg(ap, long);
    arg2 = va_arg(ap, long);
    arg3 = va_arg(ap, long);
    arg4 = va_arg(ap, long);
    arg5 = va_arg(ap, long);
    arg6 = va_arg(ap, long);
    va_end(ap);

#if !(defined(__x86_64__) && defined(__LP64__))
    if (injector->arch == ARCH_X86_64_X32) {
        injector__set_errmsg("x32-ABI target process is supported only by x86_64.");
        return INJERR_UNSUPPORTED_TARGET;
    }
#endif

    switch (injector->arch) {
#if defined(__x86_64__) && defined(__LP64__)
    case ARCH_X86_64:
    case ARCH_X86_64_X32:
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
#if defined(__x86_64__) || defined(__i386__)
    case ARCH_I386:
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
        break;
#endif
#if defined(__aarch64__)
    case ARCH_ARM64:
        /* setup instructions */
        code.u32[0] = 0xd4000001; /* svc #0 */
        code.u32[1] = BREAKINST_ARM64;
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
        break;
#endif
#if defined(__aarch64__) || defined(__arm__)
    case ARCH_ARM_EABI_THUMB:
        /* setup instructions */
        code.u16[0] = 0xdf00; /* svc #0 */
        code.u16[1] = BREAKINST_THUMB;
#ifdef __LP64__
        code.u16[2] = 0x46c0; /* nop (mov r8, r8) */
        code.u16[3] = 0x46c0; /* nop (mov r8, r8) */
#endif
        code_size = sizeof(long);
        /* setup registers */
        uregs[16] |= THUMB_MODE_BIT;
        uregs[15] = injector->code_addr;
        uregs[7] = syscall_number;
        uregs[0] = arg1;
        uregs[1] = arg2;
        uregs[2] = arg3;
        uregs[3] = arg4;
        uregs[4] = arg5;
        uregs[5] = arg6;
        reg32_return = &uregs[0];
        break;
    case ARCH_ARM_EABI:
        /* setup instructions */
        code.u32[0] = 0xef000000; /* svc #0 */
        code.u32[1] = BREAKINST_ARM;
        code_size = 2 * 4;
        /* setup registers */
        uregs[16] &= ~THUMB_MODE_BIT;
        uregs[15] = injector->code_addr;
        uregs[7] = syscall_number;
        uregs[0] = arg1;
        uregs[1] = arg2;
        uregs[2] = arg3;
        uregs[3] = arg4;
        uregs[4] = arg5;
        uregs[5] = arg6;
        reg32_return = &uregs[0];
        break;
#endif
    default:
        injector__set_errmsg("Unexpected architecture: %s", injector__arch2name(injector->arch));
        return INJERR_UNSUPPORTED_TARGET;
    }

    rv = kick_then_wait_sigtrap(injector, &regs, &code, code_size);
    if (rv != 0) {
        return rv;
    }

    if (retval != NULL) {
#if defined(__aarch64__)
        if (reg32_return != NULL) {
            if (*reg32_return <= -4096u) {
                *retval = (long)*reg32_return;
            } else {
                errno = -((int)*reg32_return);
                *retval = -1;
            }
        } else {
#endif
            if ((unsigned long)*reg_return <= -4096ul) {
                *retval = (long)*reg_return;
            } else {
                errno = -((long)*reg_return);
                *retval = -1;
            }
#if defined(__aarch64__)
        }
#endif
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
    int rv;
    user_reg_t *reg_return = NULL;
#if defined(__aarch64__)
    uint32_t *reg32_return = NULL;
    uint32_t *uregs = (uint32_t *)&regs;
#endif

    va_start(ap, function_addr);
    arg1 = va_arg(ap, long);
    arg2 = va_arg(ap, long);
    arg3 = va_arg(ap, long);
    arg4 = va_arg(ap, long);
    arg5 = va_arg(ap, long);
    arg6 = va_arg(ap, long);
    va_end(ap);

    switch (injector->arch) {
#if defined(__x86_64__) && defined(__LP64__)
    case ARCH_X86_64:
    case ARCH_X86_64_X32:
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
#if defined(__x86_64__) || defined(__i386__)
    case ARCH_I386:
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
        break;
#endif
#if defined(__aarch64__)
    case ARCH_ARM64:
        /* setup instructions */
        code.u32[0] = 0xd63f00c0; /* blr x6 */
        code.u32[1] = BREAKINST_ARM64;
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
        break;
#endif
#if defined(__aarch64__) || defined(__arm__)
    case ARCH_ARM_EABI_THUMB:
        /* setup instructions */
        code.u16[0] = 0x47a0; /* blx r4 */
        code.u16[1] = BREAKINST_THUMB;
#ifdef __LP64__
        code.u16[2] = 0x46c0; /* nop (mov r8, r8) */
        code.u16[3] = 0x46c0; /* nop (mov r8, r8) */
#endif
        code_size = sizeof(long);
        /* setup registers */
        uregs[16] |= THUMB_MODE_BIT;
        uregs[15] = injector->code_addr;
        uregs[13] = injector->stack + injector->stack_size - 16;
        uregs[4] = function_addr;
        uregs[0] = arg1;
        uregs[1] = arg2;
        uregs[2] = arg3;
        uregs[3] = arg4;
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, uregs[13] + 0, arg5);
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, uregs[13] + 4, arg6);
        reg32_return = &uregs[0];
        break;
    case ARCH_ARM_EABI:
        /* setup instructions */
        code.u32[0] = 0xe12fff34; /* blx r4 */
        code.u32[1] = BREAKINST_ARM;
        code_size = 2 * 4;
        /* setup registers */
        uregs[16] &= ~THUMB_MODE_BIT;
        uregs[15] = injector->code_addr;
        uregs[13] = injector->stack + injector->stack_size - 16;
        uregs[4] = function_addr;
        uregs[0] = arg1;
        uregs[1] = arg2;
        uregs[2] = arg3;
        uregs[3] = arg4;
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, uregs[13] + 0, arg5);
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, uregs[13] + 4, arg6);
        reg32_return = &uregs[0];
        break;
#endif
    default:
        injector__set_errmsg("Unexpected architecture: %s", injector__arch2name(injector->arch));
        return -1;
    }

    rv = kick_then_wait_sigtrap(injector, &regs, &code, code_size);
    if (rv != 0) {
        return rv;
    }

    if (retval != NULL) {
#if defined(__aarch64__)
        if (reg32_return != NULL) {
            *retval = (long)*reg32_return;
        } else {
            *retval = (long)*reg_return;
        }
#else
        *retval = (long)*reg_return;
#endif
    }
    return 0;
}

static int kick_then_wait_sigtrap(const injector_t *injector, struct user_regs_struct *regs, code_t *code, size_t code_size)
{
    int status;
    int rv;

    rv = injector__set_regs(injector, regs);
    if (rv != 0) {
        return rv;
    }
    rv = injector__write(injector, injector->code_addr, code, code_size);
    if (rv != 0) {
        injector__set_regs(injector, &injector->regs);
        return rv;
    }

    rv = injector__continue(injector);
    if (rv != 0) {
        goto cleanup;
    }
    while (1) {
        pid_t pid = waitpid(injector->pid, &status, 0);
        if (pid == -1) {
            if (errno == EINTR) {
                continue;
            }
            injector__set_errmsg("waitpid error: %s", strerror(errno));
            rv = INJERR_WAIT_TRACEE;
            goto cleanup;
        }
        if (WIFSTOPPED(status)) {
            switch (WSTOPSIG(status)) {
            case SIGTRAP:
                goto got_sigtrap;
            case SIGSTOP:
                rv = injector__continue(injector);
                if (rv != 0) {
                    goto cleanup;
                }
                break;
            default:
                injector__set_errmsg("The target process unexpectedly stopped by signal %d.", WSTOPSIG(status));
                rv = INJERR_OTHER;
                goto cleanup;
            }
        } else if (WIFEXITED(status)) {
            injector__set_errmsg("The target process unexpectedly terminated with exit code %d.", WEXITSTATUS(status));
            rv = INJERR_OTHER;
            goto cleanup;
        } else if (WIFSIGNALED(status)) {
            injector__set_errmsg("The target process unexpectedly terminated by signal %d.", WTERMSIG(status));
            rv = INJERR_OTHER;
            goto cleanup;
        } else {
            /* never reach here */
            injector__set_errmsg("Unexpected waitpid status: 0x%x", status);
            rv = INJERR_OTHER;
            goto cleanup;
        }
    }
got_sigtrap:
    /* success */
    rv = injector__get_regs(injector, regs);
cleanup:
    injector__set_regs(injector, &injector->regs);
    injector__write(injector, injector->code_addr, &injector->backup_code, code_size);
    return rv;
}
