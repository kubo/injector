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
#include <stdarg.h>
#include "injector_internal.h"

char injector__errmsg[512];
char injector__errmsg_is_set;

void injector__set_errmsg(const char *format, ...)
{
    va_list ap;
    int rv;

    /* prevent the error message from being overwritten. */
    if (injector__errmsg_is_set) {
        return;
    }
    injector__errmsg_is_set = 1;

    va_start(ap, format);
    rv = vsnprintf(injector__errmsg, sizeof(injector__errmsg), format, ap);
    va_end(ap);
    if (rv == -1 || rv >= sizeof(injector__errmsg)) {
        injector__errmsg[sizeof(injector__errmsg) - 1] = '\0';
    }
}

const char *injector__arch2name(arch_t arch)
{
    switch (arch) {
    case ARCH_X86_64:
        return "x86_64";
    case ARCH_X86_64_X32:
        return "x86_64 x32-ABI";
    case ARCH_I386:
        return "i386";
    case ARCH_ARM64:
        return "ARM64";
    case ARCH_ARM_EABI_THUMB:
        return "ARM EABI thumb";
    case ARCH_ARM_EABI:
        return "ARM EABI";
    case ARCH_MIPS_64:
        return "MIPS 64";
    case ARCH_MIPS_N32:
        return "MIPS N32 ABI";
    case ARCH_MIPS_O32:
        return "MIPS O32 ABI";
    case ARCH_POWERPC_64:
        return "PowerPC 64-bit";
    case ARCH_POWERPC:
        return "PowerPC";
    case ARCH_RISCV_64:
        return "RISC-V 64";
    case ARCH_RISCV_32:
        return "RISC-V 32";
    }
    return "?";
}
