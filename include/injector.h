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
#ifndef INJECTOR_H
#define INJECTOR_H
#include <sys/types.h>

#define INJERR_OTHER -1
#define INJERR_NO_MEMORY -2
#define INJERR_NO_PROCESS -3
#define INJERR_NO_LIBRARY -4
#define INJERR_NO_FUNCTION -4
#define INJERR_ERROR_IN_TARGET -5
#define INJERR_FILE_NOT_FOUND -6
#define INJERR_INVALID_MEMORY_AREA -7
#define INJERR_PERMISSION -8
#define INJERR_UNSUPPORTED_TARGET -9
#define INJERR_INVALID_ELF_FORMAT -10
#define INJERR_WAIT_TRACEE -11

typedef struct injector injector_t;

int injector_attach(injector_t **injector, pid_t pid);
int injector_inject(injector_t *injector, const char *path);
int injector_detach(injector_t *injector);
const char *injector_error(void);

#endif
