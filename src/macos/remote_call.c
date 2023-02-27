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
#include "mach_exc.h"
#include <stdlib.h>
#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <signal.h>

//Before change shellcode, see:
//injector.c -> injector_detach
//exc_handler.c -> catch_mach_exception_raise
#if defined(__arm64__) || defined(__aarch64__)
char* shellcode = 
	"\x00\x01\x3f\xd6"		//blr x8
	"\x00\x00\x00\x14"		//b	   //infinity loop, we will terminate this thread later
	
	//second thread
	"\x00\x00\x20\xd4"		//brk 0
	"\x00\x01\x3f\xd6"		//blr x8
	"\x00\x00\x20\xd4"		//brk 0
	"\xc0\x03\x5f\xd6"		//ret
;
int shellcode1_len = 8;
int shellcode_length = 24;
#else

char* shellcode = 
	//"\x55"				//push   rbp
	//"\x48\x89\xE5"		//mov    rbp, rsp
	//"\x48\x83\xEC\x10"	//sub    rsp, 0x10
	//"\x48\x8D\x7D\xF8"	//lea    rdi, [rbp - 8]
	"\x90"					//nop
	"\x90"					//nop
	"\x90"					//nop
	"\xFF\xD0"				//call   rax
	//"\x48\x83\xC4\x10"	//add    rsp, 0x10
	//"\x5D"				//pop    rbp
	"\xeb\xfe"				//jmp 0	   //infinity loop, we will terminate this thread later
	
	//second thread
	"\xcc"				//int3
	//"\x55"				//push   rbp
	//"\x48\x89\xe5"		//mov  rbp, rsp
	"\xff\xd0" 			//call rax
	//"\x5D" 				//pop    rbp
	"\xcc"				//int3
	"\xc3"				//ret
;
int shellcode1_len = 7;
int shellcode_length = 12;
#endif
int injector__call_function(injector_t *injector, long *retval, long function_addr, ...)
{	
	va_list ap;
	va_start(ap, function_addr);
	long arg1, arg2, arg3, arg4, arg5, arg6;
    arg1 = va_arg(ap, long);
    arg2 = va_arg(ap, long);
    arg3 = va_arg(ap, long);
    arg4 = va_arg(ap, long);
    arg5 = va_arg(ap, long);
    arg6 = va_arg(ap, long);
	va_end(ap);
	int rv;

	if(injector->shellcode_writed == 0){
		pcfmt_t pcfmt = (pcfmt_t)dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread");

		
		rv = injector__write(injector, injector->code_addr, shellcode, shellcode_length);
		if(rv != 0){
			return rv;
		}
		if(pcfmt == 0){
			//char* legacy_append = 
			//"\xFF\xD0"		//call rax
			//"\xcc"			//int3
			//;
			//rv = injector__write(injector, injector->code_addr, legacy_append, 3);
			
			//It turns out that we can call pthread_create in mach thread without _pthread_set_self on MacOS < 10.12
			pcfmt = (pcfmt_t)dlsym(RTLD_DEFAULT, "pthread_create");
		}
		rv = injector__protect(injector, injector->code_addr, injector->code_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
		if (rv != 0) {
			return rv;
		}
		injector->shellcode_writed = 1;
		injector->code2_addr = injector->code_addr + shellcode1_len;
		
		thread_act_t mach_thread;
#if defined(__arm64__) || defined(__aarch64__)
		arm_thread_state64_t state;
		memset(&state, '\0', sizeof(state));
		state.__pc = injector->code_addr;
		state.__sp = injector->stack;
		state.__x[8] = (uint64_t)pcfmt;
		state.__x[0] = injector->stack - 32;		
		
		state.__x[1] = 0;
		state.__x[2] = injector->code2_addr;
		state.__x[3] = 0;
		rv = thread_create_running(injector->remote_task, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT , &mach_thread);
#else
		x86_thread_state64_t state;
		memset(&state, '\0', sizeof(state));
		state.__rip = injector->code_addr;
		state.__rsp = injector->stack - 0x10;
		state.__rbp = injector->stack;	
		if(pcfmt == NULL){
			state.__rax = (uint64_t)dlsym(RTLD_DEFAULT, "_pthread_set_self");
			state.__rdi = 0;
			injector->func_addr = (uint64_t)dlsym(RTLD_DEFAULT, "pthread_create");
			injector->arg1 = injector->stack - 0x8;
			injector->arg2 = 0;
			injector->arg3 = injector->code2_addr;
			injector->arg4 = 0;
		} else {
			state.__rax = (uint64_t)pcfmt;
			state.__rdi = injector->stack - 0x8;//&thread
		}
		
		state.__rsi = 0;
		state.__rdx = injector->code2_addr;
		state.__rcx = 0;		

		rv = thread_create_running(injector->remote_task, x86_THREAD_STATE64, (thread_state_t)&state, x86_THREAD_STATE64_COUNT, &mach_thread);
#endif
		if(rv != 0){
			injector__set_errmsg("%s error : %s", "CREATE_THREAD", mach_error_string(rv));
			return INJERR_ERROR_IN_TARGET;
		}
		injector->mach_thread = mach_thread;
		if(pcfmt == NULL){
			injector->handle_action = TRAP_SETREGS;
			injector__handle_exc(injector);
		}
		injector->func_addr = function_addr;
		injector->arg1 = arg1;
		injector->arg2 = arg2;
		injector->arg3 = arg3;
		injector->arg4 = arg4;
		injector->arg5 = arg5;
		injector->arg6 = arg6;
	
		injector->handle_action = TRAP_SETREGS;
		injector__handle_exc(injector);
	} else {
#if defined(__arm64__) || defined(__aarch64__)

		mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
		arm_thread_state64_t state;
		rv = thread_get_state(injector->remote_thread, ARM_THREAD_STATE64, (thread_state_t)&state, &state_count);
		if(rv != 0){
			injector__set_errmsg("%s error : %s", "THREAD_GET_STATE", mach_error_string(rv));
			return INJERR_ERROR_IN_TARGET;
		}
		state.__pc = injector->code2_addr + 4;
		state.__x[0] = arg1;
		state.__x[1] = arg2;
		state.__x[2] = arg3;
		state.__x[3] = arg4;
		state.__x[4] = arg5;
		state.__x[5] = arg6;
		state.__x[8] = function_addr;
		rv = thread_set_state(injector->remote_thread, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT);
#else
		mach_msg_type_number_t state_count = x86_THREAD_STATE64_COUNT;
		x86_thread_state64_t state;
		rv = thread_get_state(injector->remote_thread, x86_THREAD_STATE64, (thread_state_t)&state, &state_count);
		if(rv != 0){
			injector__set_errmsg("%s error : %s", "THREAD_GET_STATE", mach_error_string(rv));
			return INJERR_ERROR_IN_TARGET;
		}
		state.__rip = injector->code2_addr + 1;
		state.__rax = function_addr;
		state.__rdi = arg1;
		state.__rsi = arg2;
		state.__rdx = arg3;
		state.__rcx = arg4;
		state.__r8 = arg5;
		state.__r9 = arg6;
		rv = thread_set_state(injector->remote_thread, x86_THREAD_STATE64, (thread_state_t)&state, x86_THREAD_STATE64_COUNT);
#endif
		if(rv != 0){
			injector__set_errmsg("%s error : %s", "THREAD_SET_STATE", mach_error_string(rv));
			return INJERR_ERROR_IN_TARGET;
		}
		rv = thread_resume(injector->remote_thread);
		if(rv != 0){
			injector__set_errmsg("%s error : %s", "THREAD_RESUME", mach_error_string(rv));
			return INJERR_ERROR_IN_TARGET;
		}
	}	

	injector->handle_action = TRAP_GETREGS;
	injector__handle_exc(injector);
	if(injector->handle_err != 0){
		return injector->handle_err;
	}
	*retval = injector->retval;
	return 0;
}
