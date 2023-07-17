/* -*- indent-tabs-mode: nil -*-
 *
 * injector - Library for injecting a shared library into a Linux process
 *
 * URL: https://github.com/kubo/injector
 *
 * ------------------------------------------------------
 *
 * Copyright (C) 2022 TheOiseth
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
#include <stdarg.h>
#include <libproc.h>
#include <bsm/libbsm.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>


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
#ifndef P_TRANSLATED
#define P_TRANSLATED    0x00020000
#endif
int injector__get_process_arch(pid_t pid, arch_t *arch){
    int mib[CTL_MAXNAME] = {0};
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = pid;
    size_t length = 4;
    struct kinfo_proc proc_info = {0};
    size_t size = sizeof(proc_info);

    if(sysctl(mib, (u_int)length, &proc_info, &size, NULL, 0) != 0) {
        *arch = ARCH_UNKNOWN;
        return INJERR_SUCCESS;
    }
    if (size == 0) {
        injector__set_errmsg("Process %d not found", pid);
        return INJERR_NO_PROCESS;
    }

    if(P_TRANSLATED == (P_TRANSLATED & proc_info.kp_proc.p_flag)){
        if(P_LP64 == (P_LP64 & proc_info.kp_proc.p_flag)){
            *arch = ARCH_X86_64;
            return INJERR_SUCCESS;
        } else {
            *arch = ARCH_I386;
            return INJERR_SUCCESS;
        }
    } else {
        arch_t sys_arch = injector__get_system_arch();
        if(sys_arch == ARCH_ARM64){
            *arch = ARCH_ARM64;
            return INJERR_SUCCESS;
        }
#if defined(__arm64__) || defined(__aarch64__)
        if(sys_arch == ARCH_UNKNOWN){
            *arch = ARCH_ARM64;
            return INJERR_SUCCESS;
        }
#endif
    }

    if(P_LP64 == (P_LP64 & proc_info.kp_proc.p_flag)){
        *arch = ARCH_X86_64;
        return INJERR_SUCCESS;
    }
    *arch = ARCH_I386;
    return INJERR_SUCCESS;
}

#ifndef CPU_TYPE_ARM64
#define CPU_TYPE_ARM            ((cpu_type_t) 12)
#define CPU_ARCH_ABI64          0x01000000
#define CPU_TYPE_ARM64          (CPU_TYPE_ARM | CPU_ARCH_ABI64)
#endif
arch_t injector__get_system_arch(){
	size_t size;
	cpu_type_t type = -1;
	int mib[CTL_MAXNAME] = {0};
	size_t length = CTL_MAXNAME;

	if (sysctlnametomib("sysctl.proc_cputype", mib, &length) != 0){
		return ARCH_UNKNOWN;
	}

	mib[length] = getpid();
	length++;
	size = sizeof(cpu_type_t);

	if (sysctl(mib, (u_int)length, &type, &size, 0, 0) != 0){
		return ARCH_UNKNOWN;
	}
	if (CPU_TYPE_X86_64 == type) {
		return ARCH_X86_64;
	}

	if (CPU_TYPE_ARM64 == type) {
		return ARCH_ARM64;
	}
	return ARCH_UNKNOWN;
}
const char *injector__arch2name(arch_t arch)
{
    switch (arch) {
    case ARCH_X86_64:
        return "x86_64";
    case ARCH_I386:
        return "i386";
    case ARCH_ARM64:
        return "ARM64";
    case ARCH_POWERPC_64:
        return "PowerPC 64-bit";
    case ARCH_POWERPC:
        return "PowerPC";
	case ARCH_UNKNOWN:
        return "Unknown";
    }
    return "?";
}