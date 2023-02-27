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
#include <libproc.h>
#include <signal.h>
static int set_mach_error(const char *request_name, int err)
{
    injector__set_errmsg("%s error : %s", request_name, mach_error_string(err));
    switch (err) {
    case KERN_INVALID_ADDRESS:
        return INJERR_INVALID_MEMORY_AREA;
    case KERN_NO_ACCESS:
        return INJERR_PERMISSION;
    }
    return INJERR_OTHER;
}

static int set_error(const char *request_name)
{
    int err = errno;
    injector__set_errmsg("%s error : %s", request_name, strerror(errno));
    switch (err) {
    case EFAULT:
        return INJERR_INVALID_MEMORY_AREA;
    case EPERM:
        return INJERR_PERMISSION;
    case ESRCH:
        return INJERR_NO_PROCESS;
    }
    return INJERR_OTHER;
}

int injector__task_pid(injector_t *injector)
{
	int rv = kill(injector->pid, 0);
	if(rv != 0){
		return set_error("TASK_FOR_PID");
	}
	task_t remote_task;
    rv = task_for_pid(mach_task_self(), injector->pid, &remote_task);
	
	if (rv != KERN_SUCCESS) {
		return set_mach_error("TASK_FOR_PID", rv);
	}
	injector->remote_task = remote_task;
    return 0;
}

int injector__allocate(const injector_t *injector, mach_vm_address_t *address, mach_vm_size_t size, int flags)
{
	int rv = mach_vm_allocate(injector->remote_task, address, size, flags);
    if (rv != KERN_SUCCESS) {
        return set_mach_error("ALLOCATE", rv);
    }
	return 0;
}

int injector__deallocate(const injector_t *injector, mach_vm_address_t address, mach_vm_size_t size){
	int rv = mach_vm_deallocate(injector->remote_task, address, size);
    if (rv != KERN_SUCCESS) {
        return set_mach_error("DEALLOCATE", rv);
    }
	return 0;
}

int injector__protect(const injector_t *injector, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection)
{
	int rv = mach_vm_protect(injector->remote_task, address, size, set_maximum, new_protection);
    if (rv != KERN_SUCCESS) {
        return set_mach_error("PROTECT", rv);
    }
	return 0;
}

int injector__write(const injector_t *injector, size_t addr, const void *buf, size_t len) {
	int rv = mach_vm_write(injector->remote_task, addr, (vm_offset_t)buf, len);
	if (rv != KERN_SUCCESS) {
         return set_mach_error("WRITE", rv);
    }
	return 0;
}
int injector__read(const injector_t *injector, size_t addr, void *buf, size_t len){
	mach_vm_size_t readed;
	int rv = mach_vm_read_overwrite(injector->remote_task, addr, len, (mach_vm_address_t)buf, &readed);
	if (rv != KERN_SUCCESS) {
         return set_mach_error("READ", rv);
    }
	return 0;
}

