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
#include "injector.h"
#include <stdint.h>
#include <stdbool.h>
#include <mach/mach_vm.h>
#include <mach/mach.h>
#include <errno.h>

typedef enum {
    STOP_CONTINUE,
	STOP_DETACH,
    TRAP_SETREGS,  
    TRAP_GETREGS
} handle_action_t;

struct injector {
    pid_t pid;
	uint8_t attached;
	uint8_t allocated;
	uint8_t ptrace_attached;
	uint8_t shellcode_writed;
	task_t remote_task;
    size_t code_addr;
	size_t code2_addr;
	size_t code_size;
    size_t text;
    size_t text_size;
    size_t stack;
    size_t stack_size;
	
	thread_act_t mach_thread;
	thread_act_t remote_thread;
#if defined(__arm64__) || defined(__aarch64__)
	arm_thread_state64_t remote_thread_saved_state;
#else
	x86_thread_state64_t remote_thread_saved_state;
#endif
	uint8_t state_saved;
	long func_addr;
	long arg1;
	long arg2;
	long arg3;
	long arg4;
	long arg5;
	long arg6;
	mach_port_name_t 		exc_port;
	exception_mask_t		saved_masks[EXC_TYPES_COUNT];
	mach_port_t				saved_ports[EXC_TYPES_COUNT];
	exception_behavior_t	saved_behaviors[EXC_TYPES_COUNT];
	thread_state_flavor_t	saved_flavors[EXC_TYPES_COUNT];
	mach_msg_type_number_t	saved_exception_types_count;
	handle_action_t handle_action;
	long retval;
	int handle_err;
	
};

typedef struct{
	char stub[120];
	injector_t *injector;
} mach_msg_header_with_injector;

typedef enum {
    ARCH_X86_64,
    ARCH_I386,
    ARCH_ARM64,  
    ARCH_POWERPC_64,
    ARCH_POWERPC,
	ARCH_UNKNOWN
} arch_t;



typedef int (*pcfmt_t)(pthread_t* ,pthread_attr_t* ,void *, void*);

int injector__task_pid(injector_t *injector);
int injector__allocate(const injector_t *injector, mach_vm_address_t *address, mach_vm_size_t size, int flags);
int injector__deallocate(const injector_t *injector, mach_vm_address_t address, mach_vm_size_t size);
int injector__protect(const injector_t *injector, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
int injector__write(const injector_t *injector, size_t addr, const void *buf, size_t len);
int injector__read(const injector_t *injector, size_t addr, void *buf, size_t len);
int injector__ptrace_attach(const injector_t *injector);
int injector__ptrace_detach(const injector_t *injector);
int injector__ptrace_continue(const injector_t *injector);
int injector__ptrace_update(const injector_t *injector, long thread_port);

int injector__create_exc_handler(injector_t *injector);
int injector__release_exc_handler(injector_t *injector);
int injector__handle_exc(injector_t *injector);

int injector__call_function(injector_t *injector, long *retval, long function_addr, ...);
/* util.c */
extern char injector__errmsg[];
extern char injector__errmsg_is_set;
void injector__set_errmsg(const char *format, ...);
const char *injector__arch2name(arch_t arch);
int injector__get_process_arch(pid_t pid, arch_t *arch);
arch_t injector__get_system_arch();