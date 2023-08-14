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
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/syslimits.h>
#include <signal.h>

#define STACK_SIZE 2 * 1024 * 1024
#define CODE_SIZE 512
int injector_attach(injector_t **injector_out, pid_t pid)
{
    injector_t *injector;
    arch_t self_arch, target_arch;
    int rv = 0;

    injector__errmsg_is_set = 0;

    injector = calloc(1, sizeof(injector_t));
    if (injector == NULL) {
        injector__set_errmsg("malloc error: %s", strerror(errno));
        return INJERR_NO_MEMORY;
    }
    injector->pid = pid;
	rv = injector__get_process_arch(getpid(), &self_arch);
	if (rv != 0) {
	    goto error_exit;
	}
	rv = injector__get_process_arch(pid, &target_arch);
	if (rv != 0) {
	    goto error_exit;
	}
	arch_t sys_arch = injector__get_system_arch();

	if(self_arch != ARCH_UNKNOWN && target_arch != ARCH_UNKNOWN){
		if(self_arch != target_arch){
			injector__set_errmsg("%s target process isn't supported by %s process.", injector__arch2name(target_arch), injector__arch2name(self_arch));
			rv = INJERR_UNSUPPORTED_TARGET;
			goto error_exit;
		}
		if(sys_arch == ARCH_ARM64 && self_arch != ARCH_ARM64){
			injector__set_errmsg("%s target process isn't supported by %s process on ARM64 machine.", injector__arch2name(target_arch), injector__arch2name(self_arch));
			rv = INJERR_UNSUPPORTED_TARGET;
			goto error_exit;
		}
	}

	rv = injector__task_pid(injector);
	if (rv != 0) {
		goto error_exit;
    }
	injector->attached = 1;

	rv = injector__create_exc_handler(injector);
	
	if (rv != 0) {
		goto error_exit;
    }
	rv = injector__ptrace_attach(injector);
	if(rv != 0){
		return rv;
	}
	injector->handle_action = STOP_CONTINUE;
	injector->handle_err = 0;
	do{
		injector__handle_exc(injector);
	} while(injector->handle_err != 0);
	
	injector->ptrace_attached = 1;
		
	injector->text_size = sysconf(_SC_PAGESIZE);
	injector->stack_size = STACK_SIZE;
	injector->code_size = CODE_SIZE;
	
	size_t alloc_size = injector->text_size + injector->stack_size;
	
	mach_vm_address_t addr = (vm_address_t)NULL;
	rv = injector__allocate(injector, &addr, alloc_size, VM_FLAGS_ANYWHERE);
	if (rv != 0) {
		goto error_exit;
    }
	
	mach_vm_address_t code_addr = (vm_address_t)NULL;
	rv = injector__allocate(injector, &code_addr, CODE_SIZE, VM_FLAGS_ANYWHERE);
	if (rv != 0) {
		goto error_exit;
    }
	
	injector->allocated = 1;
    injector->text = (size_t)addr;
	injector->stack = injector->text + injector->text_size + injector->stack_size / 2;	
	injector->stack &= 0xFFFFFFFFFFFFFFF0; //alignment
	injector->code_addr = (size_t)code_addr;
	
	rv = injector__protect(injector, addr, alloc_size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
	if (rv != 0) {
		goto error_exit;
    }
	
	rv = injector__protect(injector, code_addr, CODE_SIZE, FALSE, VM_PROT_READ | VM_PROT_WRITE);
	if (rv != 0) {
		goto error_exit;
    }
	*injector_out = injector;
	return 0;
error_exit:
    injector_detach(injector);
    return rv;
}

int injector_inject(injector_t *injector, const char *path, void **handle)
{
    char abspath[PATH_MAX];
    int dlflags = RTLD_LAZY;
    size_t len;
    int rv;
	long retval;
	injector__errmsg_is_set = 0;
	if (realpath(path, abspath) == NULL) {
        injector__set_errmsg("failed to get the full path of '%s': %s",
                           path, strerror(errno));
        return INJERR_FILE_NOT_FOUND;
    }
	len = strlen(abspath) + 1;
	 if (len > injector->text_size) {
        injector__set_errmsg("too long file path: %s", path);
        return INJERR_FILE_NOT_FOUND;
    }

    rv = injector__write(injector, injector->text, abspath, len);
    if (rv != 0) {
        return rv;
    }
	
	rv = injector__call_function(injector, &retval, (long)dlopen, injector->text, dlflags);
    if (rv != 0) {
        return rv;
    }
	if (retval == 0) {
        char buf[256 + 1] = {0,};
        rv = injector__call_function(injector, &retval, (long)dlerror);
        if (rv == 0 && retval != 0) {
            injector__read(injector, retval, buf, sizeof(buf) - 1);
        }
		
        if (buf[0] != '\0') {
            injector__set_errmsg("dlopen failed: %s", buf);
        } else {
            injector__set_errmsg("dlopen failed");
        }

        return INJERR_ERROR_IN_TARGET;
    }
	if (handle != NULL) {
        *handle = (void*)retval;
    }
	return 0;
}

int injector_call(injector_t *injector, void *handle, const char* name)
{
    int rv;
    long retval;
    size_t len = strlen(name) + 1;

    injector__errmsg_is_set = 0;

    if (len > injector->text_size) {
        injector__set_errmsg("too long function name: %s", name);
        return INJERR_FUNCTION_MISSING;
    }
    rv = injector__write(injector, injector->text, name, len);
    if (rv != 0) {
        return rv;
    }
    rv = injector__call_function(injector, &retval, (long)dlsym, handle, injector->text);
    if (retval == 0) {
        injector__set_errmsg("function not found: %s", name);
        return INJERR_FUNCTION_MISSING;
    }
    return injector__call_function(injector, &retval, retval);
}

int injector_uninject(injector_t *injector, void *handle)
{
    int rv;
    long retval;

    injector__errmsg_is_set = 0;

    rv = injector__call_function(injector, &retval, (long)dlclose, handle);
    if (rv != 0) {
        return rv;
    }
    if (retval != 0) {
        injector__set_errmsg("dlclose failed");
        return INJERR_ERROR_IN_TARGET;
    }
    return 0;
}

int injector_detach(injector_t *injector)
{
	int rv = 0;
    injector__errmsg_is_set = 0;
	if (injector->remote_thread != 0) {
		//For some reasons on MacOS ARM64 (tested on 12.0.1) thread_terminate() returns unknown error, so let it end by itslef
		if(injector->state_saved){
#if defined(__arm64__) || defined(__aarch64__)
			injector->remote_thread_saved_state.__pc = injector->code2_addr + 12;
			rv = thread_set_state(injector->remote_thread, ARM_THREAD_STATE64, (thread_state_t)&injector->remote_thread_saved_state, ARM_THREAD_STATE64_COUNT);
			if (rv != KERN_SUCCESS) {
				injector__set_errmsg("%s error : %s", "GET_THREAD_STATE", mach_error_string(rv));
				rv = INJERR_ERROR_IN_TARGET;
			}
#else
			injector->remote_thread_saved_state.__rip = injector->code2_addr + 4;
			rv = thread_set_state(injector->remote_thread, x86_THREAD_STATE64, (thread_state_t)&injector->remote_thread_saved_state, x86_THREAD_STATE64_COUNT);
			if (rv != KERN_SUCCESS) {
				injector__set_errmsg("%s error : %s", "GET_THREAD_STATE", mach_error_string(rv));
				rv = INJERR_ERROR_IN_TARGET;
			}
#endif
			rv = thread_resume(injector->remote_thread);
			if(rv != 0){
				injector__set_errmsg("Remote thread resume error: %s\n", mach_error_string(rv));
				rv = INJERR_ERROR_IN_TARGET;
			}
			
			//wait thread for end
#if defined(__arm64__) || defined(__aarch64__)
			thread_state_flavor_t flavor = ARM_THREAD_STATE64;
#else
			thread_state_flavor_t flavor = x86_THREAD_STATE64;
#endif
			mach_msg_type_number_t state_count;
			int counter = 0;
			while(thread_get_state(injector->remote_thread, flavor, (thread_state_t)&injector->remote_thread_saved_state, &state_count) == 0){
				counter++;
				usleep(10);
				if(counter > 1000){
					break;
				}
			}
		}	
	}
	
	if (injector->ptrace_attached) {
		injector->handle_action = STOP_DETACH;
		kill(injector->pid, SIGSTOP);		
		injector->handle_err = 0;
		do{
			injector__handle_exc(injector);
		} while(injector->handle_err != 0);
		injector__release_exc_handler(injector);
	}
	
    if (injector->allocated) {
		injector__deallocate(injector, injector->text, injector->text_size + injector->stack_size);
		injector__deallocate(injector, injector->code_addr, injector->code_size);
    }
    if (injector->attached) {
		mach_port_deallocate(mach_task_self(), injector->remote_task);
    }

    free(injector);
    return rv;
}
const char *injector_error(void)
{
    return injector__errmsg;
}