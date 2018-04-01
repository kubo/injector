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
#include <elf.h>
#include "injector_internal.h"

int injector__setup_trampoline_code(const injector_t *injector, inst_t *trampoline_code)
{
    switch (injector->e_machine) {
#if defined(__x86_64__)
    case EM_X86_64:
        /* trampoline code to call a syscall call */
        trampoline_code[0] = 0x0f;
        trampoline_code[1] = 0x05; /* 0f 05 : syscall     */
        trampoline_code[2] = 0xcc; /* cc    : int3        */
        trampoline_code[3] = 0x90; /* 90    : nop         */
        /* trampoline code to call a function */
        trampoline_code[4] = 0xff;
        trampoline_code[5] = 0xd0; /* ff d0 : callq *%rax */
        trampoline_code[6] = 0xcc; /* cc    : int3        */
        trampoline_code[7] = 0x90; /* 90    : nop         */
        break;
#endif
#if defined(__x86_64__) || defined(__i386__)
    case EM_386:
        /* trampoline code to call a syscall call */
        trampoline_code[0] = 0xcd;
        trampoline_code[1] = 0x80; /* cd 80 : int $80     */
        trampoline_code[2] = 0xcc; /* cc    : int3        */
        trampoline_code[3] = 0x90; /* 90    : nop         */
        /* trampoline code to call a function */
        trampoline_code[4] = 0xff;
        trampoline_code[5] = 0xd0; /* ff d0 : call *%eax  */
        trampoline_code[6] = 0xcc; /* cc    : int3        */
        trampoline_code[7] = 0x90; /* 90    : nop         */
        break;
#endif
#if defined(__arm__)
    case EM_ARM:
#ifdef __thumb__
        /* trampoline code to call a syscall call */
        trampoline_code[0] = 0xdf00; /* svc #0 */
        trampoline_code[1] = 0xbe00; /* bkpt #0 */
        /* trampoline code to call a function */
        trampoline_code[2] = 0x47a0; /* blx r4 */
        trampoline_code[3] = 0xbe00; /* bkpt #0 */
#else
        /* trampoline code to call a syscall call */
        trampoline_code[0] = 0xef000000; /* svc #0 */
        trampoline_code[1] = 0xe1200070; /* bkpt #0 */
        /* trampoline code to call a function */
        trampoline_code[2] = 0xe12fff34; /* blx r4 */
        trampoline_code[3] = 0xe1200070; /* bkpt #0 */
#endif
        break;
#endif
#if defined(__aarch64__)
    case EM_AARCH64:
        /* trampoline code to call a syscall call */
        trampoline_code[0] = 0xd4000001; /* svc #0 */
        trampoline_code[1] = 0xd4200000; /* brk #0 */
        /* trampoline code to call a function */
        trampoline_code[2] = 0xd63f00c0; /* blr x6 */
        trampoline_code[3] = 0xd4200000; /* brk #0 */
        break;
#endif
    default:
        injector__set_errmsg("Unsupported architecture: 0x%04x\n", injector->e_machine);
        return -1;
    }
    return 0;
}

/*
 * The arguments after syscall_number must be integer types and
 * the size must not be greater than the size of long.
 */
int injector__call_syscall(const injector_t *injector, long *retval, long syscall_number, ...)
{
    struct user_regs_struct regs = injector->regs;
    long arg1, arg2, arg3, arg4, arg5, arg6;
    va_list ap;
#ifdef __LP64__
    unsigned long long *reg_return;
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
        regs.rip = injector->trampoline_addr + TRAMPOLINE_SYSCALL_OFFSET;
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
        regs.eip = injector->trampoline_addr + TRAMPOLINE_SYSCALL_OFFSET;
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
        regs.uregs[15] = injector->trampoline_addr + TRAMPOLINE_SYSCALL_OFFSET;
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
        regs.pc = injector->trampoline_addr + TRAMPOLINE_SYSCALL_OFFSET;
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

    if (injector__run_code(injector, &regs) != 0) {
        return -1;
    }

    if (retval != NULL) {
        if (*reg_return <= -4096ul) {
            *retval = (long)*reg_return;
        } else {
            errno = -((long)*reg_return);
            *retval = -1;
        }
    }
    return 0;
}

/*
 * The arguments after function_addr must be integer types and
 * the size must not be greater than the size of long.
 */
int injector__call_function(const injector_t *injector, long *retval, long function_addr, ...)
{
    struct user_regs_struct regs = injector->regs;
    long arg1, arg2, arg3, arg4, arg5, arg6;
    va_list ap;
#ifdef __LP64__
    unsigned long long *reg_return;
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
#if defined(__x86_64__)
    case EM_X86_64:
        regs.rip = injector->trampoline_addr + TRAMPOLINE_FUNCTION_OFFSET;
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
#if defined(__x86_64__) || defined(__i386__)
        regs.eip = injector->trampoline_addr + TRAMPOLINE_FUNCTION_OFFSET;
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
        regs.uregs[15] = injector->trampoline_addr + TRAMPOLINE_FUNCTION_OFFSET;
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
        regs.pc = injector->trampoline_addr + TRAMPOLINE_FUNCTION_OFFSET;
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

    if (injector__run_code(injector, &regs) != 0) {
        return -1;
    }

    if (retval != NULL) {
        *retval = (long)*reg_return;
    }
    return 0;
}
