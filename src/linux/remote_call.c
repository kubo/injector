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
#if defined __linux__
/* Detect musl libc. See https://stackoverflow.com/a/70211227/985524  */
#define _GNU_SOURCE
#include <features.h>
#ifndef __USE_GNU
#define MUSL_LIBC
#endif // __USE_GNU
#endif // __linux__

#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <inttypes.h>
#include "injector_internal.h"

// #define INJECTOR_DEBUG_REMOTE_CALL 1

#ifdef INJECTOR_DEBUG_REMOTE_CALL
#undef DEBUG
#define DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#undef DEBUG
#define DEBUG(...) do {} while(0)
#endif

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

#ifdef __mips__
#define REG_V0 2
#define REG_A0 4
#define REG_A1 5
#define REG_A2 6
#define REG_A3 7
#define REG_A4 8
#define REG_A5 9
#define REG_T4 12
#define REG_T9 25
#define REG_SP 29
#define REG_FP 30
#define REG_RA 31

static void print_regs(const injector_t *injector, const struct pt_regs *regs)
{
    DEBUG("  Registers:\n");
    DEBUG("    -- at v0 v1: %016"PRIx64" %016"PRIx64" %016"PRIx64" %016"PRIx64"\n",
          regs->regs[0], regs->regs[1], regs->regs[2], regs->regs[3]);
    DEBUG("    a0 a1 a2 a3: %016"PRIx64" %016"PRIx64" %016"PRIx64" %016"PRIx64"\n",
          regs->regs[4], regs->regs[5], regs->regs[6], regs->regs[7]);
    DEBUG("    %s: %016"PRIx64" %016"PRIx64" %016"PRIx64" %016"PRIx64"\n",
          (injector->arch != ARCH_MIPS_O32) ? "a4 a5 a6 a7" : "t0 t1 t2 t3",
          regs->regs[8], regs->regs[9], regs->regs[10], regs->regs[11]);
    DEBUG("    t4 t5 t6 t7: %016"PRIx64" %016"PRIx64" %016"PRIx64" %016"PRIx64"\n",
          regs->regs[12], regs->regs[13], regs->regs[14], regs->regs[15]);
    DEBUG("    s0 s1 s2 s3: %016"PRIx64" %016"PRIx64" %016"PRIx64" %016"PRIx64"\n",
          regs->regs[16], regs->regs[17], regs->regs[18], regs->regs[19]);
    DEBUG("    s4 s5 s6 s7: %016"PRIx64" %016"PRIx64" %016"PRIx64" %016"PRIx64"\n",
          regs->regs[20], regs->regs[21], regs->regs[22], regs->regs[23]);
    DEBUG("    t8 t9 k0 k1: %016"PRIx64" %016"PRIx64" %016"PRIx64" %016"PRIx64"\n",
          regs->regs[24], regs->regs[25], regs->regs[26], regs->regs[27]);
    DEBUG("    gp sp s8 ra: %016"PRIx64" %016"PRIx64" %016"PRIx64" %016"PRIx64"\n",
          regs->regs[28], regs->regs[29], regs->regs[30], regs->regs[31]);
    DEBUG("    lo hi epc:                    %016"PRIx64" %016"PRIx64" %016"PRIx64"\n",
          regs->lo, regs->hi, regs->cp0_epc);
    DEBUG("    badvaddr status cause:        %016"PRIx64" %016"PRIx64" %016"PRIx64"\n",
          regs->cp0_badvaddr, regs->cp0_status, regs->cp0_cause);
}
#define PRINT_REGS(injector, regs) print_regs((injector), (regs))
#endif /* __mips__ */


#ifdef __powerpc__
static void print_regs(const injector_t *injector, const struct pt_regs *regs)
{
#undef WIDTH
#ifdef __LP64__
#define WIDTH "016"
#define softe_or_mq_str "softe"
#define softe_or_mq softe
#else
#define WIDTH "08"
#define softe_or_mq_str "mq   "
#define softe_or_mq mq
#endif
    DEBUG("  Registers:\n");
    DEBUG("    gpr0  gpr1  gpr2   gpr3   : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->gpr[0], regs->gpr[1], regs->gpr[2], regs->gpr[3]);
    DEBUG("    gpr4  gpr5  gpr6   gpr7   : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->gpr[4], regs->gpr[5], regs->gpr[6], regs->gpr[7]);
    DEBUG("    gpr8  gpr9  gpr10  gpr11  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->gpr[8], regs->gpr[9], regs->gpr[10], regs->gpr[11]);
    DEBUG("    gpr12 gpr13 gpr14  gpr15  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->gpr[12], regs->gpr[13], regs->gpr[14], regs->gpr[15]);
    DEBUG("    gpr16 gpr17 gpr18  gpr19  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->gpr[16], regs->gpr[17], regs->gpr[18], regs->gpr[19]);
    DEBUG("    gpr20 gpr21 gpr22  gpr23  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->gpr[20], regs->gpr[21], regs->gpr[22], regs->gpr[23]);
    DEBUG("    gpr24 gpr25 gpr26  gpr27  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->gpr[24], regs->gpr[25], regs->gpr[26], regs->gpr[27]);
    DEBUG("    gpr28 gpr29 gpr30  gpr31  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->gpr[28], regs->gpr[29], regs->gpr[30], regs->gpr[31]);
    DEBUG("    nip   msr   orig_gpr3 ctr : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->nip, regs->msr, regs->orig_gpr3, regs->ctr);
    DEBUG("    link  xer   ccr    "softe_or_mq_str"  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->link, regs->xer, regs->ccr, regs->softe_or_mq);
    DEBUG("    trap  dar   dsisr  result : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->trap, regs->dar, regs->dsisr, regs->result);
#undef WIDTH
}
#define PRINT_REGS(injector, regs) print_regs((injector), (regs))
#endif

#ifdef __riscv
#define REG_RA 1
#define REG_T1 6
#ifdef __LP64__
#define WIDTH "016"
#else
#define WIDTH "08"
#endif
static void print_regs(const injector_t *injector, const struct user_regs_struct *regs)
{
    DEBUG("  Registers:\n");
    DEBUG("    pc  ra  sp  gp  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->pc, regs->ra, regs->sp, regs->gp);
    DEBUG("    tp  t0  t1  t2  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->tp, regs->t0, regs->t1, regs->t2);
    DEBUG("    s0  s1  a0  a1  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->s0, regs->s1, regs->a0, regs->a1);
    DEBUG("    a2  a3  a4  a5  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->a2, regs->a3, regs->a4, regs->a5);
    DEBUG("    a6  a7  s2  s3  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->a6, regs->a7, regs->s2, regs->s3);
    DEBUG("    s4  s5  s6  s7  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->s4, regs->s5, regs->s6, regs->s7);
    DEBUG("    s8  s9  s10 s11 : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->s8, regs->s9, regs->s10, regs->s11);
    DEBUG("    t3  t4  t5  t6  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->t3, regs->t4, regs->t5, regs->t6);
}
#define PRINT_REGS(injector, regs) print_regs((injector), (regs))
#endif

/* register type used in struct user_regs_struct */
#if defined(__mips__)
typedef uint64_t user_reg_t;
#elif defined(__riscv)
typedef unsigned long user_reg_t;
#elif defined(__LP64__) && !defined(MUSL_LIBC)
typedef unsigned long long user_reg_t;
#elif defined(__i386__)
typedef long user_reg_t;
#else
typedef unsigned long user_reg_t;
#endif

static int kick_then_wait_sigtrap(const injector_t *injector, struct user_regs_struct *regs, code_t *code, size_t code_size);

#ifndef PRINT_REGS
#define PRINT_REGS(injector, regs) do {} while (0)
#endif

/*
 * Call the specified system call in the target process.
 *
 * The arguments after syscall_number must be integer types and
 * the size must not be greater than the size of long.
 */
int injector__call_syscall(const injector_t *injector, intptr_t *retval, long syscall_number, ...)
{
    struct user_regs_struct regs = injector->regs;
    code_t code;
    size_t code_size;
    long arg1, arg2, arg3, arg4, arg5, arg6;
    va_list ap;
    int rv;
#if !defined(__mips__) && !defined(__powerpc__)
    user_reg_t *reg_return = NULL;
#if defined(__aarch64__)
    uint32_t *reg32_return = NULL;
    uint32_t *uregs = (uint32_t *)&regs;
#endif
#endif

    va_start(ap, syscall_number);
    arg1 = va_arg(ap, long);
    arg2 = va_arg(ap, long);
    arg3 = va_arg(ap, long);
    arg4 = va_arg(ap, long);
    arg5 = va_arg(ap, long);
    arg6 = va_arg(ap, long);
    va_end(ap);

    DEBUG("injector__call_syscall:\n");
    DEBUG("  args: %ld, %lx, %lx, %lx, %lx, %lx, %lx\n", syscall_number, arg1, arg2, arg3, arg4, arg5, arg6);

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
#if defined(__mips__)
    case ARCH_MIPS_64:
    case ARCH_MIPS_N32:
    case ARCH_MIPS_O32:
        /* setup instructions */
        if (syscall_number > 0xffff) {
            injector__set_errmsg("too large system call number: %d", syscall_number);
            return INJERR_OTHER;
        }
        code.u32[0] = 0x00000025 | (REG_A3 << 11) | (REG_T4 << 21); /* or $a3, $t4, $zero; move $a3, $t4 */
        code.u32[1] = 0x24000000 | (REG_V0 << 16) | syscall_number; /* addiu $v0, $zero, syscall_number */
        code.u32[2] = 0x0000000c; /* syscall */
        code.u32[3] = 0x0000000d; /* break */
        code_size = 4 * 4;
        DEBUG("  Code: %08"PRIx32" %08"PRIx32" %08"PRIx32" %08"PRIx32"\n",
              code.u32[0], code.u32[1], code.u32[2], code.u32[3]);
        /* setup registers */
        regs.cp0_epc  = injector->code_addr;
        regs.regs[REG_A0] = arg1;
        regs.regs[REG_A1] = arg2;
        regs.regs[REG_A2] = arg3;
        // Use the combination of "regs.regs[REG_T4] = arg4" and "move $a3, $t4"
        // instead of "regs.regs[REG_A3] = arg4". I don't know why the latter
        // doesn't work.
        regs.regs[REG_T4] = arg4;
        if (injector->arch != ARCH_MIPS_O32) {
            /* ARCH_MIPS_64 or ARCH_MIPS_N32 */
            regs.regs[REG_A4] = arg5;
            regs.regs[REG_A5] = arg6;
        } else {
            /* ARCH_MIPS_O32 */
            regs.regs[REG_SP] -= 32;
            PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.regs[REG_SP] + 16, arg5);
            PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.regs[REG_SP] + 20, arg6);
        }
        break;
#endif
#if defined(__powerpc__)
#ifdef __LP64__
    case ARCH_POWERPC_64:
#endif
    case ARCH_POWERPC:
        /* setup instructions */
        code.u32[0] = 0x44000002; /* sc */
        code.u32[1] = 0x7fe00008; /* trap */
        code_size = 2 * 4;
        /* setup registers */
        regs.nip = injector->code_addr;
        regs.gpr[PT_R0] = syscall_number;
        regs.gpr[PT_R3] = arg1;
        regs.gpr[PT_R4] = arg2;
        regs.gpr[PT_R5] = arg3;
        regs.gpr[PT_R6] = arg4;
        regs.gpr[PT_R7] = arg5;
        regs.gpr[PT_R8] = arg6;
        break;
#endif
#if defined(__riscv)
#ifdef __LP64__
    case ARCH_RISCV_64:
#endif
    case ARCH_RISCV_32:
        /* setup instructions */
        code.u32[0] = 0x00000073; /* ecall */
        code.u32[1] = 0x00100073; /* ebreak */
        code_size = 2 * 4;
        DEBUG("  Code: %08"PRIx32" %08"PRIx32"\n",
              code.u32[0], code.u32[1]);
        /* setup registers */
        regs.pc  = injector->code_addr;
        regs.a0 = arg1;
        regs.a1 = arg2;
        regs.a2 = arg3;
        regs.a3 = arg4;
        regs.a4 = arg5;
        regs.a5 = arg6;
        regs.a7 = syscall_number;
        reg_return = &regs.a0;
        break;
#endif
    default:
        injector__set_errmsg("Unexpected architecture: %s", injector__arch2name(injector->arch));
        return INJERR_UNSUPPORTED_TARGET;
    }

    PRINT_REGS(injector, &regs);
    rv = kick_then_wait_sigtrap(injector, &regs, &code, code_size);
    if (rv != 0) {
        return rv;
    }
    PRINT_REGS(injector, &regs);

    if (retval != NULL) {
#if defined(__mips__)
        if (regs.regs[REG_A3] == 0) {
            *retval = (intptr_t)regs.regs[REG_V0];
        } else {
            errno = (int)regs.regs[REG_V0];
            *retval = -1;
        }
#elif defined(__powerpc__)
        /* https://github.com/strace/strace/blob/v5.19/src/linux/powerpc/get_error.c#L21-L26 */
        if (regs.ccr & 0x10000000) {
            errno = (int)regs.gpr[PT_R3];
            *retval = -1;
        } else {
            *retval = (intptr_t)regs.gpr[PT_R3];
        }
#else
#if defined(__aarch64__)
        if (reg32_return != NULL) {
            if (*reg32_return <= -4096u) {
                *retval = (intptr_t)*reg32_return;
            } else {
                errno = -((int)*reg32_return);
                *retval = -1;
            }
        } else {
#endif
            if ((unsigned long)*reg_return <= -4096ul) {
                *retval = (intptr_t)*reg_return;
            } else {
                errno = -((int)*reg_return);
                *retval = -1;
            }
#if defined(__aarch64__)
        }
#endif
#endif /* defined(__mips__) */
    }
    return 0;
}

/*
 * Call the function at the specified address in the target process.
 *
 * The arguments after function_addr must be integer types and
 * the size must not be greater than the size of long.
 */
int injector__call_function(const injector_t *injector, intptr_t *retval, long function_addr, ...)
{
    va_list ap;
    int rv;
    va_start(ap, function_addr);
    rv = injector__call_function_va_list(injector, retval, function_addr, ap);
    va_end(ap);
    return rv;
}

/*
 * Call the function at the specified address in the target process.
 *
 * The arguments after function_addr must be integer types and
 * the size must not be greater than the size of long.
 */
int injector__call_function_va_list(const injector_t *injector, intptr_t *retval, long function_addr, va_list ap)
{
    struct user_regs_struct regs = injector->regs;
    code_t code;
    size_t code_size;
    long arg1, arg2, arg3, arg4, arg5, arg6;
    int rv;
    user_reg_t *reg_return = NULL;
#if defined(__aarch64__)
    uint32_t *reg32_return = NULL;
    uint32_t *uregs = (uint32_t *)&regs;
#endif

    arg1 = va_arg(ap, long);
    arg2 = va_arg(ap, long);
    arg3 = va_arg(ap, long);
    arg4 = va_arg(ap, long);
    arg5 = va_arg(ap, long);
    arg6 = va_arg(ap, long);

    DEBUG("injector__call_function:\n");
    DEBUG("  args: %lx, %lx, %lx, %lx, %lx, %lx, %lx\n", function_addr, arg1, arg2, arg3, arg4, arg5, arg6);

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
        /* rsp must be aligned to a 16-byte boundary. */
        regs.rsp = injector->stack + injector->stack_size - (2 * 16);
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
#if defined(__mips__)
    case ARCH_MIPS_64:
    case ARCH_MIPS_N32:
    case ARCH_MIPS_O32:
        /* setup instructions */
        code.u32[0] = 0x00000009 | (REG_RA << 11) | (REG_T9 << 21); /* jalr $t9;  */
        code.u32[1] = 0x00000025 | (REG_A3 << 11) | (REG_T4 << 21); /* or $a3, $t4, $zero; in a delay slot */
        code.u32[2] = 0x0000000d; /* break */
        code.u32[3] = 0x00000000; /* nop */
        code_size = 4 * 4;
        DEBUG("  Code: %08"PRIx32" %08"PRIx32" %08"PRIx32" %08"PRIx32"\n",
              code.u32[0], code.u32[1], code.u32[2], code.u32[3]);
        /* setup registers */
        regs.cp0_epc  = injector->code_addr;
        regs.regs[REG_FP] = injector->stack + injector->stack_size - 32;
        regs.regs[REG_SP] = injector->stack + injector->stack_size - 64;
        regs.regs[REG_T9] = function_addr;
        regs.regs[REG_A0] = arg1;
        regs.regs[REG_A1] = arg2;
        regs.regs[REG_A2] = arg3;
        regs.regs[REG_T4] = arg4;
        if (injector->arch != ARCH_MIPS_O32) {
            /* ARCH_MIPS_64 or ARCH_MIPS_N32 */
            regs.regs[REG_A4] = arg5;
            regs.regs[REG_A5] = arg6;
        } else {
            /* ARCH_MIPS_O32 */
            PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.regs[REG_SP] + 16, arg5);
            PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.regs[REG_SP] + 20, arg6);
        }
        reg_return = &regs.regs[REG_V0];
        break;
#endif
#if defined(__powerpc__)
#ifdef __LP64__
    case ARCH_POWERPC_64:
#endif
    case ARCH_POWERPC:
        /* setup instructions */
        code.u32[0] = 0x4e800421; /* bctrl */
        code.u32[1] = 0x7fe00008; /* trap */
        code_size = 2 * 4;
        /* setup registers */
        regs.nip = injector->code_addr;
        regs.gpr[PT_R1] = injector->stack + injector->stack_size - 256;
        regs.ctr = function_addr;
        regs.gpr[PT_R3] = arg1;
        regs.gpr[PT_R4] = arg2;
        regs.gpr[PT_R5] = arg3;
        regs.gpr[PT_R6] = arg4;
        regs.gpr[PT_R7] = arg5;
        regs.gpr[PT_R8] = arg6;
        regs.gpr[PT_R12] = function_addr;
        reg_return = &regs.gpr[PT_R3];
        break;
#endif
#if defined(__riscv)
#ifdef __LP64__
    case ARCH_RISCV_64:
#endif
    case ARCH_RISCV_32:
        /* setup instructions */
        code.u32[0] = 0x00000067 | (REG_RA << 7) | (REG_T1 << 15) ; /* jalr t1 */
        code.u32[1] = 0x00100073; /* ebreak */
        code_size = 2 * 4;
        DEBUG("  Code: %08"PRIx32" %08"PRIx32"\n",
              code.u32[0], code.u32[1]);
        /* setup registers */
        regs.pc = injector->code_addr;
        regs.sp = injector->stack + injector->stack_size - 16;
        regs.t1 = function_addr;
        regs.a0 = arg1;
        regs.a1 = arg2;
        regs.a2 = arg3;
        regs.a3 = arg4;
        regs.a4 = arg5;
        regs.a5 = arg6;
        reg_return = &regs.a0;
        break;
#endif
    default:
        injector__set_errmsg("Unexpected architecture: %s", injector__arch2name(injector->arch));
        return -1;
    }

    PRINT_REGS(injector, &regs);
    rv = kick_then_wait_sigtrap(injector, &regs, &code, code_size);
    if (rv != 0) {
        return rv;
    }
    PRINT_REGS(injector, &regs);

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
#if defined(PT_GETSIGINFO)
            siginfo_t si = {0,};
#endif
            switch (WSTOPSIG(status)) {
            case SIGTRAP:
                goto got_sigtrap;
            case SIGSTOP:
                rv = injector__continue(injector);
                if (rv != 0) {
                    goto cleanup;
                }
                break;
#if defined(PT_GETSIGINFO)
            case SIGSYS:
              PTRACE_OR_RETURN(PT_GETSIGINFO, injector, 0, (long)&si);
              if (si.si_signo == SIGSYS && si.si_code == 1) {
                  injector__set_errmsg("Got SIGSYS. System call %d at address %p might be blocked by seccomp.",
                                       si.si_syscall, (void*)si.si_call_addr);
                  rv = INJERR_OTHER;
                  goto cleanup;
              }
              // FALL THROUGH */
#endif
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
