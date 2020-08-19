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
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <stdio.h>
#include <stdarg.h>
#include <malloc.h>
#include <windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include "injector.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "dbghelp.lib")
#if !defined(PSAPI_VERSION) || PSAPI_VERSION == 1
#pragma comment(lib, "psapi.lib")
#endif

static DWORD page_size = 0;
static size_t func_LoadLibraryW;
static size_t func_FreeLibrary;
static size_t func_GetLastError;
static char errmsg[512];

// extern HMODULE load_address;
// DWORD load_library(const wchar_t *path)
// {
//    HMODULE hMod = LoadLibraryW(path);
//    if (hMod != NULL) {
//        load_address = hMod;
//        return 0;
//    } else {
//        return GetLastError();
//    }
// }
// DWORD unload_library(HMODULE handle)
// {
//    if (FreeLibrary(handle)) {
//        return 0;
//    } else {
//        return GetLastError();
//    }
// }
#ifdef _M_AMD64
static const char code64_template[] =
    // ---------- call LoadLibraryW ----------
    /* 0000:     */ "\x48\x83\xEC\x28"             // sub  rsp,28h
    /* 0004:     */ "\xFF\x15\x3E\x00\x00\x00"     // call LoadLibraryW
    //                       ^^^^^^^^^^^^^^^^0x0000003e = ADDR64_LoadLibraryW - (0x0004 + 6)
    /* 000A:     */ "\x48\x85\xC0"                 // test rax,rax
    /* 000D:     */ "\x74\x0B"                     // je   L1
    /* 000F:     */ "\x48\x89\x05\xEA\x0F\x00\x00" // mov  [load_address], rax
    //                           ^^^^^^^^^^^^^^^^0x00000fea = 0x1000 - (0x000F + 7)
    /* 0016:     */ "\x33\xC0"                     // xor  eax,eax
    /* 0018:     */ "\xEB\x06"                     // jmp  L2
    /* 001A: L1: */ "\xFF\x15\x38\x00\x00\x00"     // call GetLastError
    //                       ^^^^^^^^^^^^^^^^0x00000038 = ADDR64_GetLastError - (0x001A + 6)
    /* 0020: L2: */ "\x48\x83\xC4\x28"             // add  rsp,28h
    /* 0024:     */ "\xC3"                         // ret

    // ---------- call FreeLibrary ----------
#define UNINJECTION_CODE64_OFFSET 0x25
    /* 0025:     */ "\x48\x83\xEC\x28"             // sub  rsp,28h
    /* 0029:     */ "\xFF\x15\x21\x00\x00\x00"     // call FreeLibrary
    //                       ^^^^^^^^^^^^^^^^0x00000021 = ADDR64_FreeLibrary - (0x0029 + 6)
    /* 002F:     */ "\x85\xC0"                     // test eax,eax
    /* 0031:     */ "\x74\x04"                     // je   L1
    /* 0033:     */ "\x33\xC0"                     // xor  eax,eax
    /* 0035:     */ "\xEB\x06"                     // jmp  L2
    /* 0037: L1: */ "\xFF\x15\x1B\x00\x00\x00"     // call GetLastError
    //                       ^^^^^^^^^^^^^^^^0x0000001B = ADDR64_GetLastError - (0x0037 + 6)
    /* 003D: L2: */ "\x48\x83\xC4\x28"             // add  rsp,28h
    /* 0041:     */ "\xC3"                         // ret

    // padding
    /* 0042:     */ "\x90\x90\x90\x90\x90\x90"

    // ---------- literal pool ----------
#define ADDR64_LoadLibraryW  0x0048
    /* 0048:     */ "\x90\x90\x90\x90\x90\x90\x90\x90"
#define ADDR64_FreeLibrary   0x0050
    /* 0050:     */ "\x90\x90\x90\x90\x90\x90\x90\x90"
#define ADDR64_GetLastError  0x0058
    /* 0058:     */ "\x90\x90\x90\x90\x90\x90\x90\x90"
    ;

#define CODE64_SIZE          0x0060
#endif

#ifdef _M_ARM64
static const unsigned int code64_template[] = {
    // ---------- call LoadLibraryW ----------
    /* 0000:     */ 0xF81F0FFE, //  str   lr,[sp,#-0x10]!
    /* 0004:     */ 0x580002A9, //  ldr   x9,$ADDR_LoadLibraryW
    /* 0008:     */ 0xD63F0120, //  blr   x9
    /* 000C:     */ 0xB40000A0, //  cbz   x0,$L1
    /* 0010:     */ 0xB0000001, //  adrp  x1, #0x1000
    /* 0014:     */ 0xF9000020, //  str   x0, [x1]
    /* 0018:     */ 0x52800000, //  mov   w0,#0
    /* 001C:     */ 0x14000003, //  b     $L2
    /* 0020: L1: */ 0x58000249, //  ldr   x9,$ADDR_GetLastError
    /* 0024:     */ 0xD63F0120, //  blr   x9
    /* 0028: L2: */ 0xF84107FE, //  ldr   lr,[sp],#0x10
    /* 002C:     */ 0xD65F03C0, //  ret

    // ---------- call FreeLibrary ----------
#define UNINJECTION_CODE_OFFSET 0x0030
    /* 0030:     */ 0xF81F0FFE, //  str   lr,[sp,#-0x10]!
    /* 0034:     */ 0x58000169, //  ldr   x9,$ADDR_FreeLibrary
    /* 0038:     */ 0xD63F0120, //  blr   x9
    /* 003C:     */ 0xB4000060, //  cbz   x0,$L1
    /* 0040:     */ 0x52800000, //  mov   w0,#0
    /* 0044:     */ 0x14000003, //  b     $L2
    /* 0048: L1: */ 0x58000109, //  ldr   x9,$ADDR_GetLastError
    /* 004C:     */ 0xD63F0120, //  blr   x9
    /* 0050: L2: */ 0xF84107FE, //  ldr   lr,[sp],#0x10
    /* 0054:     */ 0xD65F03C0, //  ret

    // ---------- literal pool ----------
#define ADDR_LoadLibraryW    0x0058
    /* 0058:     */ 0, 0,
#define ADDR_FreeLibrary     0x0060
    /* 0060:     */ 0, 0,
#define ADDR_GetLastError    0x0068
    /* 0068:     */ 0, 0
};
#define CODE64_SIZE          0x0070
#endif

#if defined(_M_AMD64) || defined(_M_IX86)
static const char code32_template[] =
    // ---------- call LoadLibraryW ----------
    /* 0000:     */ "\xFF\x74\x24\x04"          // push dword ptr [esp+4]
#define CALL_LoadLibraryW    0x0004
    /* 0004:     */ "\xE8\x00\x00\x00\x00"      // call LoadLibraryW@4
    /* 0009:     */ "\x85\xC0"                  // test eax,eax
    /* 000B:     */ "\x74\x09"                  // je   L1
#define MOV_EAX  0x000D
    /* 000D:     */ "\xA3\x00\x00\x00\x00"      // mov  dword ptr [load_address], eax
    /* 0012:     */ "\x33\xC0"                  // xor  eax,eax
    /* 0014:     */ "\xEB\x05"                  // jmp  L2
#define CALL_GetLastError1   0x0016
    /* 0016: L1: */ "\xE8\x00\x00\x00\x00"      // call GetLastError@0
    /* 001B: L2: */ "\xC2\x04\x00"              // ret  4

    // ---------- call FreeLibrary ----------
#define UNINJECTION_CODE_OFFSET 0x001E
    /* 001E:     */ "\xFF\x74\x24\x04"          // push dword ptr [esp+4]
#define CALL_FreeLibrary     0x0022
    /* 0022:     */ "\xE8\x00\x00\x00\x00"      // call FreeLibrary@4
    /* 0027:     */ "\x85\xC0"                  // test eax,eax
    /* 0029:     */ "\x74\x04"                  // je   L1
    /* 002B:     */ "\x33\xC0"                  // xor  eax,eax
    /* 002D:     */ "\xEB\x05"                  // jmp  L2
#define CALL_GetLastError2   0x002F
    /* 002F: L1: */ "\xE8\x00\x00\x00\x00"      // call GetLastError@0
    /* 0034: L2: */ "\xC2\x04\x00"              // ret  4
    ;

#define CODE32_SIZE          0x0037
#endif

#ifdef _WIN64
#define CODE_SIZE CODE64_SIZE
#else
#define CODE_SIZE CODE32_SIZE
#endif

static void set_errmsg(const char *format, ...);
static const char *w32strerr(DWORD err);

struct injector {
    HANDLE hProcess;
    char *remote_mem;
    char *uninjection_code;
};

static BOOL init(void)
{
    SYSTEM_INFO si;
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;
    HMODULE kernel32 = GetModuleHandleA("kernel32");

    GetSystemInfo(&si);
    page_size = si.dwPageSize;
    func_LoadLibraryW = (size_t)GetProcAddress(kernel32, "LoadLibraryW");
    func_FreeLibrary = (size_t)GetProcAddress(kernel32, "FreeLibrary");
    func_GetLastError = (size_t)GetProcAddress(kernel32, "GetLastError");

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        return FALSE;
    }
    if (!LookupPrivilegeValue(0, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return TRUE;
}

#ifdef _M_AMD64
static int cmp_func(const void *context, const void *key, const void *datum)
{
    ptrdiff_t rva_to_va = (ptrdiff_t)context;
    const char *k = (const char *)key;
    const char *d = (const char *)(rva_to_va + *(const DWORD*)datum);
    return strcmp(k, d);
}

static int funcaddr(DWORD pid, size_t *load_library, size_t *free_library, size_t *get_last_error)
{
    HANDLE hSnapshot;
    MODULEENTRY32W me;
    BOOL ok;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hFileMapping = NULL;
    void *base = NULL;
    IMAGE_NT_HEADERS *nt_hdrs;
    ULONG exp_size;
    const IMAGE_EXPORT_DIRECTORY *exp;
    const DWORD *names, *name, *funcs;
    const WORD *ordinals;
    ptrdiff_t rva_to_va;
    int rv = INJERR_OTHER;

    /* Get the full path of kernel32.dll. */
retry:
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        switch (err) {
        case ERROR_BAD_LENGTH:
            goto retry;
        case ERROR_ACCESS_DENIED:
            rv = INJERR_PERMISSION;
            break;
        case ERROR_INVALID_PARAMETER:
            rv = INJERR_NO_PROCESS;
            break;
        default:
            rv = INJERR_OTHER;
        }
        set_errmsg("CreateToolhelp32Snapshot error: %s", w32strerr(err));
        return rv;
    }
    me.dwSize = sizeof(me);
    for (ok = Module32FirstW(hSnapshot, &me); ok; ok = Module32NextW(hSnapshot, &me)) {
        if (wcsicmp(me.szModule, L"kernel32.dll") == 0) {
            break;
        }
    }
    CloseHandle(hSnapshot);
    if (!ok) {
        set_errmsg("kernel32.dll could not be found.");
        return INJERR_OTHER;
    }

    /* Get the export directory in the kernel32.dll. */
    hFile = CreateFileW(me.szExePath, GENERIC_READ, 0, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        set_errmsg("failed to open file %s: %s", me.szExePath, w32strerr(GetLastError()));
        goto exit;
    }
    hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hFileMapping == NULL) {
        set_errmsg("failed to create file mapping of %s: %s", me.szExePath, w32strerr(GetLastError()));
        goto exit;
    }
    base = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (base == NULL) {
        set_errmsg("failed to map file %s to memory: %s", me.szExePath, w32strerr(GetLastError()));
        goto exit;
    }
    nt_hdrs = ImageNtHeader(base);
    if (nt_hdrs == NULL) {
        set_errmsg("ImageNtHeader error: %s", w32strerr(GetLastError()));
        goto exit;
    }
    exp = (const IMAGE_EXPORT_DIRECTORY *)ImageDirectoryEntryToDataEx(base, FALSE, IMAGE_DIRECTORY_ENTRY_EXPORT, &exp_size, NULL);
    if (exp == NULL) {
        set_errmsg("ImageDirectoryEntryToDataEx error: %s", w32strerr(GetLastError()));
        goto exit;
    }
    if (exp->NumberOfNames == 0) {
        set_errmsg("No export entires are not found.");
        goto exit;
    }
    names = (const DWORD*)ImageRvaToVa(nt_hdrs, base, exp->AddressOfNames, NULL);
    if (names == NULL) {
        set_errmsg("ImageRvaToVa error: %s", w32strerr(GetLastError()));
        goto exit;
    }
    ordinals = (const WORD*)ImageRvaToVa(nt_hdrs, base, exp->AddressOfNameOrdinals, NULL);
    if (ordinals == NULL) {
        set_errmsg("ImageRvaToVa error: %s", w32strerr(GetLastError()));
        goto exit;
    }
    funcs = (const DWORD*)ImageRvaToVa(nt_hdrs, base, exp->AddressOfFunctions, NULL);
    if (funcs == NULL) {
        set_errmsg("ImageRvaToVa error: %s", w32strerr(GetLastError()));
        goto exit;
    }
    rva_to_va = (size_t)ImageRvaToVa(nt_hdrs, base, names[0], NULL) - (size_t)names[0];

    /* Find the address of LoadLibraryW */
    name = bsearch_s((void*)"LoadLibraryW", names, exp->NumberOfNames, sizeof(DWORD), cmp_func, (void*)rva_to_va);
    if (name == NULL) {
        set_errmsg("Could not find the address of LoadLibraryW");
        goto exit;
    }
    *load_library = (size_t)me.modBaseAddr + funcs[ordinals[name - names]];

    /* Find the address of FreeLibrary */
    name = bsearch_s((void*)"FreeLibrary", names, exp->NumberOfNames, sizeof(DWORD), cmp_func, (void*)rva_to_va);
    if (name == NULL) {
        set_errmsg("Could not find the address of FreeLibrary");
        goto exit;
    }
    *free_library = (size_t)me.modBaseAddr + funcs[ordinals[name - names]];

    /* Find the address of GetLastError */
    name = bsearch_s((void*)"GetLastError", names, exp->NumberOfNames, sizeof(DWORD), cmp_func, (void*)rva_to_va);
    if (name == NULL) {
        set_errmsg("Could not find the address of GetLastError");
        goto exit;
    }
    *get_last_error = (size_t)me.modBaseAddr + funcs[ordinals[name - names]];
    rv = 0;
exit:
    if (base != NULL) {
        UnmapViewOfFile(base);
    }
    if (hFileMapping != NULL) {
        CloseHandle(hFileMapping);
    }
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
    return rv;
}
#endif

int injector_attach(injector_t **injector_out, DWORD pid)
{
    injector_t *injector;
    DWORD dwDesiredAccess =
        PROCESS_QUERY_LIMITED_INFORMATION | /* for IsWow64Process() */
        PROCESS_CREATE_THREAD |  /* for CreateRemoteThread() */
        PROCESS_VM_OPERATION  |  /* for VirtualAllocEx() */
        PROCESS_VM_READ       |  /* for ReadProcessMemory() */
        PROCESS_VM_WRITE;        /* for WriteProcessMemory() */
    BOOL is_wow64_proc;
    DWORD old_protect;
    SIZE_T written;
    int rv;
    char code[CODE_SIZE];
    size_t code_size;
    size_t load_library, free_library, get_last_error;

    if (page_size == 0) {
        init();
    }

    load_library = func_LoadLibraryW;
    free_library = func_FreeLibrary;
    get_last_error = func_GetLastError;

    injector = calloc(1, sizeof(injector_t));
    if (injector == NULL) {
        set_errmsg("malloc error: %s", strerror(errno));
        return INJERR_NO_MEMORY;
    }
    injector->hProcess = OpenProcess(dwDesiredAccess, FALSE, pid);
    if (injector->hProcess == NULL) {
        DWORD err = GetLastError();
        set_errmsg("OpenProcess error: %s", w32strerr(err));
        switch (err) {
        case ERROR_ACCESS_DENIED:
            rv = INJERR_PERMISSION;
            break;
        case ERROR_INVALID_PARAMETER:
            rv = INJERR_NO_PROCESS;
            break;
        default:
            rv = INJERR_OTHER;
        }
        goto error_exit;
    }

    IsWow64Process(injector->hProcess, &is_wow64_proc);
#ifdef _M_ARM64
    if (is_wow64_proc) {
        set_errmsg("32-bit target process isn't supported by ARM64 process.");
        rv = INJERR_UNSUPPORTED_TARGET;
        goto error_exit;
    }
#endif
#ifdef _M_IX86
    if (!is_wow64_proc) {
        IsWow64Process(GetCurrentProcess(), &is_wow64_proc);
        if (is_wow64_proc) {
            /* This process is running on Windows x64. */
            set_errmsg("64-bit target process isn't supported by 32-bit process.");
            rv = INJERR_UNSUPPORTED_TARGET;
            goto error_exit;
        }
    }
#endif
    injector->remote_mem = VirtualAllocEx(injector->hProcess, NULL, 2 * page_size,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
    if (injector->remote_mem == NULL) {
        set_errmsg("VirtualAllocEx error: %s", w32strerr(GetLastError()));
        rv = INJERR_OTHER;
        goto error_exit;
    }
    injector->uninjection_code = injector->remote_mem + UNINJECTION_CODE_OFFSET;

    if (!VirtualProtectEx(injector->hProcess, injector->remote_mem + page_size, page_size, PAGE_READWRITE, &old_protect)) {
        set_errmsg("VirtualProtectEx error: %s", w32strerr(GetLastError()));
        rv = INJERR_OTHER;
        goto error_exit;
    }
#ifdef _M_AMD64
    if (is_wow64_proc) {
        rv = funcaddr(pid, &load_library, &free_library, &get_last_error);
        if (rv != 0) {
            goto error_exit;
        }
#endif
#if defined(_M_AMD64) || defined(_M_IX86)
        /* 32-bit x86 process */
        memcpy(code, code32_template, CODE32_SIZE);
        code_size = CODE32_SIZE;
        *(unsigned int*)(code + CALL_LoadLibraryW + 1) = load_library - ((unsigned int)(size_t)injector->remote_mem + CALL_LoadLibraryW + 5);
        *(unsigned int*)(code + MOV_EAX + 1) = (unsigned int)(size_t)injector->remote_mem + page_size;
        *(unsigned int*)(code + CALL_GetLastError1 + 1) = get_last_error - ((unsigned int)(size_t)injector->remote_mem + CALL_GetLastError1 + 5);
        *(unsigned int*)(code + CALL_FreeLibrary + 1) = free_library - ((unsigned int)(size_t)injector->remote_mem + CALL_FreeLibrary + 5);
        *(unsigned int*)(code + CALL_GetLastError2 + 1) = get_last_error - ((unsigned int)(size_t)injector->remote_mem + CALL_GetLastError2 + 5);
#endif
#ifdef _M_AMD64
    } else {
        /* 64-bit x64 process */
        memcpy(code, code64_template, CODE64_SIZE);
        code_size = CODE64_SIZE;
        *(size_t*)(code + ADDR64_LoadLibraryW) = load_library;
        *(size_t*)(code + ADDR64_FreeLibrary) = free_library;
        *(size_t*)(code + ADDR64_GetLastError) = get_last_error;
        injector->uninjection_code = injector->remote_mem + UNINJECTION_CODE64_OFFSET;
    }
#endif
#ifdef _M_ARM64
    memcpy(code, code64_template, CODE64_SIZE);
    code_size = CODE64_SIZE;
    *(size_t*)(code + ADDR_LoadLibraryW) = load_library;
    *(size_t*)(code + ADDR_FreeLibrary) = free_library;
    *(size_t*)(code + ADDR_GetLastError) = get_last_error;
#endif
    if (!WriteProcessMemory(injector->hProcess, injector->remote_mem, code, code_size, &written)) {
        set_errmsg("WriteProcessMemory error: %s", w32strerr(GetLastError()));
        rv = INJERR_OTHER;
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
    DWORD pathlen = (DWORD)strlen(path);
    wchar_t *wpath;
    DWORD wpathlen;

    if (pathlen == 0) {
        set_errmsg("The specified path is empty.");
        return INJERR_FILE_NOT_FOUND;
    }
    if (pathlen > MAX_PATH) {
        set_errmsg("too long file path: %s", path);
        return INJERR_FILE_NOT_FOUND;
    }

    wpath = _alloca((pathlen + 1) * sizeof(wchar_t));
    wpathlen = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, path, pathlen, wpath, pathlen + 1);
    wpath[wpathlen] = L'\0';
    return injector_inject_w(injector, wpath, handle);
}

int injector_inject_w(injector_t *injector, const wchar_t *path, void **handle)
{
    struct {
        void *load_address;
        wchar_t fullpath[MAX_PATH];
    } data = {NULL,};
    DWORD pathlen;
    SIZE_T written;
    HANDLE hThread;
    DWORD err;

    pathlen = GetFullPathNameW(path, MAX_PATH, data.fullpath, NULL);
    if (pathlen > MAX_PATH) {
        set_errmsg("too long file path: %S", path);
        return INJERR_FILE_NOT_FOUND;
    }
    if (pathlen == 0) {
        set_errmsg("failed to get the full path: %S", path);
        return INJERR_FILE_NOT_FOUND;
    }
    if (!WriteProcessMemory(injector->hProcess, injector->remote_mem + page_size, &data, sizeof(data), &written)) {
        set_errmsg("WriteProcessMemory error: %s", w32strerr(GetLastError()));
        return INJERR_OTHER;
    }
    hThread = CreateRemoteThread(injector->hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)injector->remote_mem, injector->remote_mem + page_size + sizeof(void*), 0, NULL);
    if (hThread == NULL) {
        set_errmsg("CreateRemoteThread error: %s", w32strerr(GetLastError()));
        return INJERR_OTHER;
    }
    WaitForSingleObject(hThread, INFINITE);
    GetExitCodeThread(hThread, &err);
    CloseHandle(hThread);
    if (err != 0) {
        set_errmsg("LoadLibrary in the target process failed: %s", w32strerr(err));
        return INJERR_ERROR_IN_TARGET;
    }
    if (!ReadProcessMemory(injector->hProcess, injector->remote_mem + page_size, &data, sizeof(void *), &written)) {
        set_errmsg("ReadProcessMemory error: %s", w32strerr(GetLastError()));
        return INJERR_OTHER;
    }
    if (handle != NULL) {
        *handle = data.load_address;
    }
    return 0;
}

int injector_uninject(injector_t *injector, void *handle)
{
    HANDLE hThread;
    DWORD err;

    hThread = CreateRemoteThread(injector->hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)(injector->uninjection_code), handle, 0, NULL);
    if (hThread == NULL) {
        set_errmsg("CreateRemoteThread error: %s", w32strerr(GetLastError()));
        return INJERR_OTHER;
    }
    WaitForSingleObject(hThread, INFINITE);
    GetExitCodeThread(hThread, &err);
    CloseHandle(hThread);
    if (err != 0) {
        set_errmsg("FreeLibrary in the target process failed: %s", w32strerr(err));
        return INJERR_ERROR_IN_TARGET;
    }
    return 0;
}

int injector_detach(injector_t *injector)
{
    if (injector->remote_mem != NULL) {
        VirtualFreeEx(injector->hProcess, injector->remote_mem, 0, MEM_RELEASE);
    }
    if (injector->hProcess != NULL) {
        CloseHandle(injector->hProcess);
    }
    free(injector);
    return 0;
}

const char *injector_error(void)
{
    return errmsg;
}

static void set_errmsg(const char *format, ...)
{
    va_list ap;
    int rv;

    va_start(ap, format);
    rv = vsnprintf(errmsg, sizeof(errmsg), format, ap);
    va_end(ap);
    if (rv == -1 || rv >= sizeof(errmsg)) {
        errmsg[sizeof(errmsg) - 1] = '\0';
    }
}

static const char *w32strerr(DWORD err)
{
    static char errmsg[512];
    DWORD len;

    len = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                         NULL, err, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                         errmsg, sizeof(errmsg), NULL);
    if (len > 0) {
        while (len > 0) {
            char c = errmsg[len - 1];
            if (c == ' ' || c == '\n' || c == '\r') {
                len--;
            } else {
                break;
            }
        }
        errmsg[len] = '\0';
    } else if ((int)err >= 0) {
        sprintf(errmsg, "win32 error code %d", err);
    } else {
        sprintf(errmsg, "win32 error code 0x%x", err);
    }
    return errmsg;
}
