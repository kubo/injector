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
#include <mach/exception_types.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <stdbool.h>
#define HANDLE_EXC EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_SOFTWARE | EXC_MASK_BREAKPOINT | EXC_MASK_CRASH | EXC_MASK_CORPSE_NOTIFY
boolean_t mach_exc_server(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP);
int injector__create_exc_handler(injector_t *injector) {
	mach_port_name_t 		exc_port = 0;
	mach_msg_type_number_t	exception_types_count;
	int rv;
	injector->exc_port = 0;
	injector->saved_exception_types_count = 0;
	rv = task_get_exception_ports(injector->remote_task,
                        EXC_MASK_ALL,
                        injector->saved_masks,
                        &exception_types_count,
                        injector->saved_ports,
                        injector->saved_behaviors,
                        injector->saved_flavors);
						
	injector->saved_exception_types_count = exception_types_count;
	if(rv != 0){
		injector__set_errmsg("%s error : %s", "EXC_GET_PORTS", mach_error_string(rv));
		return INJERR_OTHER;
	}
 
	rv = mach_port_allocate(mach_task_self(),
                   MACH_PORT_RIGHT_RECEIVE,
                   &exc_port);
 	injector->exc_port = exc_port;	
 	if(rv != 0){
		injector__set_errmsg("%s error : %s", "EXC_PORT_ALLOCATE", mach_error_string(rv));
		rv = INJERR_OTHER;
		goto cleanup;
	}
	rv = mach_port_insert_right(mach_task_self(),
                       exc_port,
						exc_port,
                       MACH_MSG_TYPE_MAKE_SEND);
	if(rv != 0){
		injector__set_errmsg("%s error : %s", "EXC_INSERT_RIGHTS", mach_error_string(rv));
		rv = INJERR_OTHER;
		goto cleanup;
	}
	
	rv = task_set_exception_ports(injector->remote_task,
                         HANDLE_EXC,
                         exc_port,
                         EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
                         THREAD_STATE_NONE);
	if(rv != 0){
		injector__set_errmsg("%s error : %s", "EXC_SET_PORTS", mach_error_string(rv));
		rv = INJERR_OTHER;
		goto cleanup;
	}

	return 0;
cleanup:
	injector__release_exc_handler(injector);
return rv;	
}
int injector__handle_exc(injector_t *injector) {
	char req[128], rpl[128];
	mach_msg_header_with_injector *mmhwi;
	int rv;

	mmhwi = (mach_msg_header_with_injector*)req;
	mmhwi->injector = injector;
	rv = mach_msg((mach_msg_header_t *)req, MACH_RCV_MSG, 0, sizeof(req), injector->exc_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL); 
	if (rv != KERN_SUCCESS) {
		injector__set_errmsg("%s error : %s", "EXC_RECV_MACH_MSG", mach_error_string(rv));
		return INJERR_OTHER;
	}
/* suspend all threads in the process after an exception was received */
 
	task_suspend(injector->remote_task);

	boolean_t message_parsed_correctly = mach_exc_server((mach_msg_header_t *)req, (mach_msg_header_t *)rpl);
	if (! message_parsed_correctly) {
		 
		size_t parse_exc = ((mig_reply_error_t *)rpl)->RetCode;
		if(parse_exc != 0 ){
			injector__set_errmsg("%s error : %s", "mach_exc_server", mach_error_string(parse_exc));
		}
	}
	task_resume(injector->remote_task);
	mach_msg_size_t send_sz = ((mach_msg_header_t *)rpl)->msgh_size;
 
	rv = mach_msg((mach_msg_header_t *)rpl, MACH_SEND_MSG, send_sz, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	if (rv != KERN_SUCCESS) {
		injector__set_errmsg("%s error : %s", "EXC_SEND_MACH_MSG", mach_error_string(rv));
		return INJERR_OTHER;
	}
	return 0;
}

static bool isSIGSTOP(exception_type_t exception_type, mach_exception_data_t codes){
	return exception_type == EXC_SOFTWARE && codes[0] == EXC_SOFT_SIGNAL && codes[1] == SIGSTOP;
}

kern_return_t catch_mach_exception_raise(
    mach_port_t exception_port, 
    mach_port_t thread_port,
    mach_port_t task_port,
    exception_type_t exception_type,
    mach_exception_data_t codes,
    mach_msg_type_number_t num_codes,
	injector_t *injector)
{
	injector->handle_err = 0;	
	bool bad_exc = true;
	int rv;
	switch (injector->handle_action)
	{
		case STOP_CONTINUE:
			if(isSIGSTOP(exception_type, codes)){
				bad_exc = false;
				injector__ptrace_update(injector, thread_port);
			}
			break;
		case STOP_DETACH:
			if(isSIGSTOP(exception_type, codes)){
				bad_exc = false;
				injector__ptrace_detach(injector);
			}
			break;
		case TRAP_GETREGS:
			if(exception_type == EXC_BREAKPOINT){
				bad_exc = false;
#if defined(__arm64__) || defined(__aarch64__)
				mach_msg_type_number_t thread_state_count = ARM_THREAD_STATE64_COUNT;
				arm_thread_state64_t state;
				rv = thread_get_state(thread_port, ARM_THREAD_STATE64, (thread_state_t)&state, &thread_state_count);
				if (rv == KERN_SUCCESS) {
					injector->retval = state.__x[0];
				} else {
					injector__set_errmsg("%s error : %s", "GET_THREAD_STATE", mach_error_string(rv));
					injector->handle_err = INJERR_ERROR_IN_TARGET;
				}
#else
				mach_msg_type_number_t thread_state_count = x86_THREAD_STATE64_COUNT;
				x86_thread_state64_t state;
				rv = thread_get_state(thread_port, x86_THREAD_STATE64, (thread_state_t)&state, &thread_state_count);
				if (rv == KERN_SUCCESS) {
					injector->retval = state.__rax;
				} else {
					injector__set_errmsg("%s error : %s", "GET_THREAD_STATE", mach_error_string(rv));
					injector->handle_err = INJERR_ERROR_IN_TARGET;
				}
#endif
				if (injector->mach_thread != 0){
					rv = thread_terminate(injector->mach_thread);
					injector->mach_thread = 0;
				}
				rv = thread_suspend(thread_port);
				if(rv != KERN_SUCCESS){
					injector__set_errmsg("%s error : %s", "THREAD_SUSPEND", mach_error_string(rv));
					injector->handle_err = INJERR_ERROR_IN_TARGET;
				}
				//we don't need to continue since we already called task_resume and mach_msg later
				//rv = injector__ptrace_continue(injector);
				
			}
			break;
		case TRAP_SETREGS:
			if(exception_type == EXC_BREAKPOINT){
				bad_exc = false;
				bool thread_init = false;
				if(thread_port != injector->mach_thread){
					thread_init = injector->remote_thread == 0;
					injector->remote_thread = thread_port;
				}
#if defined(__arm64__) || defined(__aarch64__)
				mach_msg_type_number_t thread_state_count = ARM_THREAD_STATE64_COUNT;
				arm_thread_state64_t state;
				rv = thread_get_state(thread_port, ARM_THREAD_STATE64, (thread_state_t)&state, &thread_state_count);
				if (rv != KERN_SUCCESS) {
					injector__set_errmsg("%s error : %s", "GET_THREAD_STATE", mach_error_string(rv));
					injector->handle_err = INJERR_ERROR_IN_TARGET;
					goto exit;
				}
				if(thread_init){
					memcpy(&injector->remote_thread_saved_state, &state, sizeof(state));
					injector->state_saved = 1;
				}
				state.__x[0] = injector->arg1;
				state.__x[1] = injector->arg2;
				state.__x[2] = injector->arg3;
				state.__x[3] = injector->arg4;
				state.__x[4] = injector->arg5;
				state.__x[5] = injector->arg6;
				state.__x[8] = injector->func_addr;
				state.__sp = injector->stack;
				state.__pc = injector->code2_addr + 4;
				rv = thread_set_state(thread_port, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT);
				if (rv != KERN_SUCCESS) {
					injector__set_errmsg("%s error : %s", "SET_THREAD_STATE", mach_error_string(rv));
					injector->handle_err = INJERR_ERROR_IN_TARGET;
				}
#else			
				mach_msg_type_number_t thread_state_count = x86_THREAD_STATE64_COUNT;
				x86_thread_state64_t state;

				rv = thread_get_state(thread_port, x86_THREAD_STATE64, (thread_state_t)&state, &thread_state_count);
				if (rv != KERN_SUCCESS) {
					injector__set_errmsg("%s error : %s", "GET_THREAD_STATE", mach_error_string(rv));
					injector->handle_err = INJERR_ERROR_IN_TARGET;
					goto exit;
				}
				if(thread_init){
					memcpy(&injector->remote_thread_saved_state, &state, sizeof(state));
					injector->state_saved = 1;
				}
				state.__rax = injector->func_addr;
				state.__rdi = injector->arg1;
				state.__rsi = injector->arg2;
				state.__rdx = injector->arg3;
				state.__rcx = injector->arg4;
				state.__r8 = injector->arg5;
				state.__r9 = injector->arg6;
				state.__rsp = injector->stack;
				state.__rbp = injector->stack;	
				rv = thread_set_state(thread_port, x86_THREAD_STATE64, (thread_state_t)&state, x86_THREAD_STATE64_COUNT);
				if (rv != KERN_SUCCESS) {
					injector__set_errmsg("%s error : %s", "SET_THREAD_STATE", mach_error_string(rv));
					injector->handle_err = INJERR_ERROR_IN_TARGET;
				}
#endif
				//we don't need to continue since we already called task_resume and mach_msg later
				//rv = injector__ptrace_continue(injector);

			}
			break;
	}

	if(bad_exc){
		if(exception_type == EXC_SOFTWARE){
			injector__set_errmsg("The target process got an unexpected signal %i.", codes[1]);			
		} else {
			injector__set_errmsg("Got unhandled exception %i.", exception_type);
		}	
		injector->handle_err = INJERR_OTHER;
	}
exit:
    return KERN_SUCCESS;
}
 
kern_return_t catch_mach_exception_raise_state(
    mach_port_t exception_port, 
    exception_type_t exception,
    const mach_exception_data_t code, 
    mach_msg_type_number_t codeCnt,
    int *flavor, 
    const thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt, 
    thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt)
{
    return MACH_RCV_INVALID_TYPE;
}
 
kern_return_t catch_mach_exception_raise_state_identity(
    mach_port_t exception_port, 
    mach_port_t thread, 
    mach_port_t task,
    exception_type_t exception, 
    mach_exception_data_t code,
    mach_msg_type_number_t codeCnt, 
    int *flavor, 
    thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt, 
    thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt)
{
    return MACH_RCV_INVALID_TYPE;
}

int injector__release_exc_handler(injector_t *injector) {
	for (int i = 0; i < injector->saved_exception_types_count; i++) {
		task_set_exception_ports(injector->remote_task, injector->saved_masks[i], injector->saved_ports[i], injector->saved_behaviors[i], injector->saved_flavors[i]);
	}	
	injector->saved_exception_types_count = 0;
	if (injector->exc_port != 0){
		mach_port_deallocate(mach_task_self(), injector->exc_port);
		injector->exc_port = 0;
	}
	return 0;
}