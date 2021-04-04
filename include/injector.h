/* -*- indent-tabs-mode: nil -*-
 *
 * injector - Library for injecting a shared library into a Linux process
 *
 * URL: https://github.com/kubo/injector
 *
 * ------------------------------------------------------
 *
 * Copyright (C) 2018-2019 Kubo Takehiro <kubo@jiubao.org>
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
#ifndef INJECTOR_H
#define INJECTOR_H

#if defined(_WIN32)
#include <windows.h>
#define injector_pid_t DWORD
#else
#include <sys/types.h>
#define injector_pid_t pid_t
#endif

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

#define INJERR_SUCCESS 0               /* linux, windows */
#define INJERR_OTHER -1                /* linux, windows */
#define INJERR_NO_MEMORY -2            /* linux, windows */
#define INJERR_NO_PROCESS -3           /* linux, windows */
#define INJERR_NO_LIBRARY -4           /* linux */
#define INJERR_NO_FUNCTION -4          /* linux */
#define INJERR_ERROR_IN_TARGET -5      /* linux, windows */
#define INJERR_FILE_NOT_FOUND -6       /* linux, windows */
#define INJERR_INVALID_MEMORY_AREA -7  /* linux */
#define INJERR_PERMISSION -8           /* linux, windows */
#define INJERR_UNSUPPORTED_TARGET -9   /* linux, windows */
#define INJERR_INVALID_ELF_FORMAT -10  /* linux */
#define INJERR_WAIT_TRACEE -11         /* linux */
#define INJERR_FUNCTION_MISSING -12    /* linux, windows */

typedef struct injector injector_t;

int injector_attach(injector_t **injector, injector_pid_t pid);
int injector_inject(injector_t *injector, const char *path, void **handle);
int injector_call(injector_t *injector, void *handle, const char* name);
int injector_uninject(injector_t *injector, void *handle);
int injector_detach(injector_t *injector);
const char *injector_error(void);

#if defined(_WIN32)
int injector_inject_w(injector_t *injector, const wchar_t *path, void **handle);
#endif

#if 0
{
#endif
#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif
