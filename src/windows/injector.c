/* -*- indent-tabs-mode: nil -*-
 *
 * injector - Library for injecting a shared library into a Linux process
 *
 * URL: https://github.com/kubo/injector
 *
 * ------------------------------------------------------
 *
 * Copyright (C) 2018-2023 Kubo Takehiro <kubo@jiubao.org>
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
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <malloc.h>
#include <windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include "injector.h"

#if !defined(WDK_NTDDI_VERSION) || WDK_NTDDI_VERSION < 0x0A00000B
// Windows SDK version < 10.0.22000.0
#define ProcessMachineTypeInfo 9
typedef enum _MACHINE_ATTRIBUTES {
    UserEnabled    = 0x00000001,
    KernelEnabled  = 0x00000002,
    Wow64Container = 0x00000004
} MACHINE_ATTRIBUTES;
typedef struct _PROCESS_MACHINE_INFORMATION {
    USHORT ProcessMachine;
    USHORT Res0;
    MACHINE_ATTRIBUTES MachineAttributes;
} PROCESS_MACHINE_INFORMATION;
#endif

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "dbghelp.lib")
#if !defined(PSAPI_VERSION) || PSAPI_VERSION == 1
#pragma comment(lib, "psapi.lib")
#endif

typedef BOOL (WINAPI *IsWow64Process2_t)(HANDLE hProcess, USHORT *pProcessMachine, USHORT *pNativeMachine);
typedef BOOL (WINAPI *GetProcessInformation_t)(HANDLE hProcess, PROCESS_INFORMATION_CLASS ProcessInformationClass, LPVOID ProcessInformation, DWORD ProcessInformationSize);

static DWORD page_size = 0;
static size_t func_LoadLibraryW;
static size_t func_FreeLibrary;
static size_t func_GetLastError;
static size_t func_GetProcAddress;
static char errmsg[512];

typedef struct {
    uint64_t func;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
    uint64_t arg5;
    uint64_t arg6;
} remote_call_args_t;

// size_t remote_call(remote_call_args_t *args)
// {
//    size_t rv = args->func(args->arg1, args->arg2, args->arg3, args->arg4, args->arg5, args->arg6);
//    *(DWORD*)args = GetLastError();
//    return rv;
// }
static const char x64_code_template[] =

    /* 0000: */ "\x40\x53"                 // push rbx
    /* 0002: */ "\x48\x8B\xD9"             // mov  rbx,rcx   ; preserve the first argument
    /* 0005: */ "\x48\x83\xEC\x30"         // sub  rsp,30h   ; align the stack pointer
    /* 0009: */ "\x48\x8B\x41\x30"         // mov  rax,qword ptr [rcx+30h] ; set the 6th argument
    /* 000D: */ "\x48\x89\x44\x24\x28"     // mov  qword ptr [rsp+28h],rax ;   ditto
    /* 0012: */ "\x48\x8B\x41\x28"         // mov  rax,qword ptr [rcx+28h] ; set the 5th argument
    /* 0016: */ "\x48\x89\x44\x24\x20"     // mov  qword ptr [rsp+20h],rax ;   ditto
    /* 001B: */ "\x4C\x8B\x49\x20"         // mov  r9,qword ptr [rcx+20h]  ; set the 4th argument
    /* 001F: */ "\x4C\x8B\x41\x18"         // mov  r8,qword ptr [rcx+18h]  ; set the 3rd argument
    /* 0023: */ "\x48\x8B\x51\x10"         // mov  rdx,qword ptr [rcx+10h] ; set the 2nd argument
    /* 0027: */ "\x48\x8B\x49\x08"         // mov  rcx,qword ptr [rcx+8]   ; set the 1st argument
    /* 002B: */ "\xFF\x13"                 // call qword ptr [rbx]         ; call func
    /* 002D: */ "\x48\x89\x03"             // mov  qword ptr [rbx],rax     ; store the return value
    /* 0030: */ "\xFF\x15\x0A\x00\x00\x00" // call GetLastError
    /* 0036: */ "\x48\x83\xC4\x30"         // add  rsp,30h
    /* 003A: */ "\x5B"                     // pop  rbx
    /* 003B: */ "\xC3"                     // ret
    /* 003C: */ "\x90\x90\x90\x90"         // nop; nop; nop; nop
#define X64_ADDR_GetLastError  0x0040
    /* 0040: */ "\x90\x90\x90\x90\x90\x90\x90\x90"
    ;
#define X64_CODE_SIZE          0x0048

static const uint32_t arm64_code_template[] = {
    /* 0000: */ 0xa9be7bfd, // stp x29, x30, [sp, #-32]! ; prolog
    /* 0004: */ 0x910003fd, // mov x29, sp               ; ditto
    /* 0008: */ 0xf9000bf3, // str x19, [sp, #16]        ; reserve x19
    /* 000c: */ 0xaa0003f3, // mov x19, x0               ; set args to x19
    /* 0010: */ 0xa9429664, // ldp x4, x5, [x19, #40]    ; set 5th and 6th arguments
    /* 0014: */ 0xa9418e62, // ldp x2, x3, [x19, #24]    ; set 3rd and 4th arguments
    /* 0018: */ 0xa9408660, // ldp x0, x1, [x19, #8]     ; set 1st and 2nd arguments
    /* 001c: */ 0xf9400269, // ldr x9, [x19]             ; get args->func
    /* 0020: */ 0xd63f0120, // blr x9                    ; call args->func
    /* 0024: */ 0xf9000260, // str x0, [x19]             ; set the return value
    /* 0028: */ 0xf9400bf3, // ldr x19, [sp, #16]        ; restore x19
    /* 002c: */ 0xa8c27bfd, // ldp x29, x30, [sp], #32   ; epilog
    /* 0030: */ 0x58000049, // ldr x9, ARM64_ADDR_GetLastError
    /* 0034: */ 0xd61f0120, // br  x9
#define ARM64_ADDR_GetLastError    0x0038
    /* 0038: */ 0,
    /* 003c: */ 0,
};
#define ARM64_CODE_SIZE          0x0040

static const uint16_t armt_code_template[] = {
    /* 0000: */ 0xb530, // push {r4, r5, lr}   ; prolog
    /* 0002: */ 0xb083, // sub  sp, #12        ; reserve stack for arguments
    /* 0004: */ 0x0004, // movs r4, r0
    /* 0006: */ 0x6b25, // ldr  r5, [r4, #48]  ; set the 6th argument
    /* 0008: */ 0x9501, // str  r5, [sp, #4]   ;   ditto
    /* 000a: */ 0x6aa5, // ldr  r5, [r4, #40]  ; set the 5th argument
    /* 000c: */ 0x9500, // str  r5, [sp, #0]   ;   ditto
    /* 000e: */ 0x6a23, // ldr  r3, [r4, #32]  ; set the 4th argument
    /* 0010: */ 0x69a2, // ldr  r2, [r4, #24]  ; set the 3rd argument
    /* 0012: */ 0x6921, // ldr  r1, [r4, #16]   ; set the 2nd argument
    /* 0014: */ 0x68a0, // ldr  r0, [r4, #8]   ; set the 1st argument
    /* 0016: */ 0x6825, // ldr  r5, [r4, #0]   ; get args->func
    /* 0018: */ 0x47a8, // blx  r5             ; call args->func
    /* 001a: */ 0x6020, // str  r0, [r4, #0]   ; set the return value
    /* 001c: */ 0x4d01, // ldr  r5, [pc, #4]   ; get the address of GetLastError (0x0024)
    /* 001e: */ 0x47a8, // blx  r5             ; call GetLastError
    /* 0020: */ 0xb003, // add  sp, #12        ; restore stack
    /* 0022: */ 0xbd30, // pop  {r4, r5, pc}   ; epilog
#define ARMT_ADDR_GetLastError    0x0024
    /* 0024: */ 0,      // .word
    /* 0026: */ 0,      // .word
};
#define ARMT_CODE_SIZE          0x0028

static const char x86_code_template[] =
    /* 0000: */ "\x55"                 // push ebp
    /* 0001: */ "\x8B\xEC"             // mov  ebp,esp
    /* 0003: */ "\x53"                 // push ebx
    /* 0004: */ "\x8B\x5D\x08"         // mov  ebx,dword ptr [ebp+8] ; get args
    /* 0007: */ "\xFF\x73\x30"         // push dword ptr [ebx+30h]   ; set the 6th argument
    /* 000A: */ "\xFF\x73\x28"         // push dword ptr [ebx+28h]   ; set the 5th argument
    /* 000D: */ "\xFF\x73\x20"         // push dword ptr [ebx+20h]   ; set the 4th argument
    /* 0010: */ "\xFF\x73\x18"         // push dword ptr [ebx+18h]   ; set the 3rd argument
    /* 0013: */ "\xFF\x73\x10"         // push dword ptr [ebx+10h]     ; set the 2nd argument
    /* 0016: */ "\xFF\x73\x08"         // push dword ptr [ebx+8]     ; set the 1st argument
    /* 0019: */ "\xFF\x13"             // call dword ptr [ebx]       ; call args->func
    /* 001B: */ "\x89\x03"             // mov  dword ptr [ebx],eax   ; store the return value
#define X86_CALL_GetLastError   0x001D
    /* 001D: */ "\xE8\x00\x00\x00\x00" // call GetLastError
    /* 0022: */ "\x8B\x5D\xF8"         // mov  ebx,dword ptr [ebp-8]
    /* 0025: */ "\xC9"                 // leave
    /* 0026: */ "\xC2\x04\x00"         // ret  4
    ;

#define X86_CODE_SIZE          0x0029

#ifdef _M_AMD64
#define CURRENT_ARCH "x64"
#define CURRENT_IMAGE_FILE_MACHINE IMAGE_FILE_MACHINE_AMD64
#endif
#ifdef _M_ARM64
#define CURRENT_ARCH "arm64"
#define CURRENT_IMAGE_FILE_MACHINE IMAGE_FILE_MACHINE_ARM64
#endif
#ifdef _M_ARMT
#define CURRENT_ARCH "arm"
#define CURRENT_IMAGE_FILE_MACHINE IMAGE_FILE_MACHINE_ARMNT
#endif
#ifdef _M_IX86
#define CURRENT_ARCH "x86"
#define CURRENT_IMAGE_FILE_MACHINE IMAGE_FILE_MACHINE_I386
#endif

#define CODE_SIZE __max(__max(X64_CODE_SIZE, ARM64_CODE_SIZE), __max(X86_CODE_SIZE, ARMT_CODE_SIZE))

static BOOL CallIsWow64Process2(HANDLE hProcess, USHORT *pProcessMachine, USHORT *pNativeMachine)
{
    static IsWow64Process2_t IsWow64Process2_func = (IsWow64Process2_t)-1;
    if (IsWow64Process2_func == (IsWow64Process2_t)-1) {
        IsWow64Process2_func = (IsWow64Process2_t)GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process2");
    }
    if (IsWow64Process2_func == NULL) {
       return FALSE;
    }
    return IsWow64Process2_func(hProcess, pProcessMachine, pNativeMachine);
}
#define IsWow64Process2 CallIsWow64Process2

static BOOL CallGetProcessInformation(HANDLE hProcess, PROCESS_INFORMATION_CLASS ProcessInformationClass, LPVOID ProcessInformation, DWORD ProcessInformationSize)
{
    static GetProcessInformation_t GetProcessInformation_func = (GetProcessInformation_t)-1;
    if (GetProcessInformation_func == (GetProcessInformation_t)-1) {
        GetProcessInformation_func = (GetProcessInformation_t)GetProcAddress(GetModuleHandleA("kernel32"), "GetProcessInformation");
    }
    if (GetProcessInformation_func == NULL) {
       return FALSE;
    }
    return GetProcessInformation_func(hProcess, ProcessInformationClass, ProcessInformation, ProcessInformationSize);
}
#define GetProcessInformation CallGetProcessInformation

static void set_errmsg(const char *format, ...);
static const char *w32strerr(DWORD err);
static USHORT process_arch(HANDLE hProcess);
static const char *arch_name(USHORT arch);

struct injector {
    HANDLE hProcess;
    USHORT arch;
    char *code;
    char *data;
    size_t load_library;
    size_t free_library;
    size_t get_last_error;
    size_t get_proc_address;
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
    func_GetProcAddress = (size_t)GetProcAddress(kernel32, "GetProcAddress");
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

static DWORD name_index(IMAGE_NT_HEADERS *nt_hdrs, void *base, const DWORD *names, DWORD num_names, const char *name)
{
    DWORD idx;
    for (idx = 0; idx < num_names; idx++) {
        if (strcmp((const char*)ImageRvaToVa(nt_hdrs, base, names[idx], NULL), name) == 0) {
            return idx;
        }
    }
    set_errmsg("Could not find the address of %s", name);
    return (DWORD)-1;
}

static int funcaddr(DWORD pid, injector_t *injector)
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
    const DWORD *names, *funcs;
    const WORD *ordinals;
    DWORD idx;
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
    hFile = CreateFileW(me.szExePath, GENERIC_READ, FILE_SHARE_READ, NULL,
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

    /* Find the address of LoadLibraryW */
    idx = name_index(nt_hdrs, base, names, exp->NumberOfNames, "LoadLibraryW");
    if (idx == (DWORD)-1) {
        goto exit;
    }
    injector->load_library = (size_t)me.modBaseAddr + funcs[ordinals[idx]];

    /* Find the address of FreeLibrary */
    idx = name_index(nt_hdrs, base, names, exp->NumberOfNames, "FreeLibrary");
    if (idx == (DWORD)-1) {
        goto exit;
    }
    injector->free_library = (size_t)me.modBaseAddr + funcs[ordinals[idx]];

    /* Find the address of GetProcAddress */
    idx = name_index(nt_hdrs, base, names, exp->NumberOfNames, "GetProcAddress");
    if (idx == (DWORD)-1) {
        goto exit;
    }
    injector->get_proc_address = (size_t)me.modBaseAddr + funcs[ordinals[idx]];

    /* Find the address of GetLastError */
    idx = name_index(nt_hdrs, base, names, exp->NumberOfNames, "GetLastError");
    if (idx == (DWORD)-1) {
        goto exit;
    }
    injector->get_last_error = (size_t)me.modBaseAddr + funcs[ordinals[idx]];
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

static int remote_call(injector_t *injector, remote_call_args_t *args, size_t size, intptr_t *retval, DWORD *last_error)
{
    char *code = injector->code;
    HANDLE hThread;
    SIZE_T sz;

    if (injector->arch == IMAGE_FILE_MACHINE_ARMNT) {
        ++code;
    }
    if (!WriteProcessMemory(injector->hProcess, injector->data, args, size, &sz)) {
        set_errmsg("WriteProcessMemory error: %s", w32strerr(GetLastError()));
        return INJERR_OTHER;
    }
    hThread = CreateRemoteThread(injector->hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)code, injector->data, 0, NULL);
    if (hThread == NULL) {
        set_errmsg("CreateRemoteThread error: %s", w32strerr(GetLastError()));
        return INJERR_OTHER;
    }
    WaitForSingleObject(hThread, INFINITE);
    if (last_error) {
        GetExitCodeThread(hThread, last_error);
    }
    CloseHandle(hThread);
    if (retval) {
        union {
            size_t s;
            uint32_t u32;
        } val;
        size_t valsize = sizeof(size_t);
        switch (injector->arch) {
          case IMAGE_FILE_MACHINE_ARMNT:
          case IMAGE_FILE_MACHINE_I386:
              valsize = 4;
              break;
        }
        if (!ReadProcessMemory(injector->hProcess, injector->data, &val, valsize, &sz)) {
            set_errmsg("ReadProcessMemory error: %s", w32strerr(GetLastError()));
            return INJERR_OTHER;
        }
        if (valsize == 4) {
            *retval = val.u32;
        } else {
            *retval = val.s;
        }
    }
    return 0;
}

int injector_attach(injector_t **injector_out, DWORD pid)
{
    injector_t *injector;
    DWORD dwDesiredAccess =
        PROCESS_QUERY_LIMITED_INFORMATION | /* for IsWow64Process() */
        PROCESS_CREATE_THREAD |  /* for CreateRemoteThread() */
        PROCESS_VM_OPERATION  |  /* for VirtualAllocEx() */
        PROCESS_VM_READ       |  /* for ReadProcessMemory() */
        PROCESS_VM_WRITE;        /* for WriteProcessMemory() */
    DWORD old_protect;
    SIZE_T written;
    int rv;
    char code[CODE_SIZE];
    size_t code_size;

    if (page_size == 0) {
        init();
    }

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
    injector->load_library = func_LoadLibraryW;
    injector->free_library = func_FreeLibrary;
    injector->get_last_error = func_GetLastError;
    injector->get_proc_address = func_GetProcAddress;

    injector->arch = process_arch(injector->hProcess);
    switch (injector->arch) {
#if defined(_M_ARM64) // arm64
    case IMAGE_FILE_MACHINE_ARM64:
    case IMAGE_FILE_MACHINE_ARMNT:
        break;
#endif
#if defined(_M_AMD64) // x64
        static USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    case IMAGE_FILE_MACHINE_AMD64:
        break;
    case IMAGE_FILE_MACHINE_I386:
        if (native_machine == IMAGE_FILE_MACHINE_UNKNOWN) {
            USHORT dummy;
            if (!IsWow64Process2(GetCurrentProcess(), &dummy, &native_machine)) {
                native_machine = IMAGE_FILE_MACHINE_AMD64;
            }
        }
        if (native_machine == IMAGE_FILE_MACHINE_AMD64) {
            // x86 process on Windows x64
            break;
        }
        // x86 process on Windows arm64
        // FALL THROUGH
#endif
#if defined(_M_IX86) // x86
    case IMAGE_FILE_MACHINE_I386:
        break;
#endif
#if defined(_M_ARMT) // arm32
    case IMAGE_FILE_MACHINE_ARMNT:
        break;
#endif
    default:
        set_errmsg("%s target process isn't supported by %s process.",
                   arch_name(injector->arch), CURRENT_ARCH);
        rv = INJERR_UNSUPPORTED_TARGET;
        goto error_exit;
    }

    if (injector->arch != CURRENT_IMAGE_FILE_MACHINE) {
        rv = funcaddr(pid, injector);
        if (rv != 0) {
            goto error_exit;
        }
    }

    injector->code = VirtualAllocEx(injector->hProcess, NULL, 2 * page_size,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
    if (injector->code == NULL) {
        set_errmsg("VirtualAllocEx error: %s", w32strerr(GetLastError()));
        rv = INJERR_OTHER;
        goto error_exit;
    }
    injector->data = injector->code + page_size;
    switch (injector->arch) {
    case IMAGE_FILE_MACHINE_AMD64: /* x64 */
        memcpy(code, x64_code_template, X64_CODE_SIZE);
        code_size = X64_CODE_SIZE;
        *(size_t*)(code + X64_ADDR_GetLastError) = injector->get_last_error;
        break;
    case IMAGE_FILE_MACHINE_ARM64: /* arm64 */
        memcpy(code, arm64_code_template, ARM64_CODE_SIZE);
        code_size = ARM64_CODE_SIZE;
        *(size_t*)(code + ARM64_ADDR_GetLastError) = injector->get_last_error;
        break;
    case IMAGE_FILE_MACHINE_ARMNT: /* arm (thumb mode) */
        memcpy(code, armt_code_template, ARMT_CODE_SIZE);
        code_size = ARMT_CODE_SIZE;
        *(uint32_t*)(code + ARMT_ADDR_GetLastError) = (uint32_t)injector->get_last_error;
        break;
    case IMAGE_FILE_MACHINE_I386: /* x86 */
        memcpy(code, x86_code_template, X86_CODE_SIZE);
        code_size = X86_CODE_SIZE;
#define FIX_CALL_RELATIVE(addr, offset) *(uint32_t*)(code + offset + 1) = addr - ((uint32_t)(size_t)injector->code + offset + 5)
        FIX_CALL_RELATIVE(injector->get_last_error, X86_CALL_GetLastError);
        break;
    default:
        set_errmsg("Never reach here: arch=0x%x", injector->arch);
        rv = INJERR_OTHER;
        goto error_exit;
    }

    if (!WriteProcessMemory(injector->hProcess, injector->code, code, code_size, &written)) {
        set_errmsg("WriteProcessMemory error: %s", w32strerr(GetLastError()));
        rv = INJERR_OTHER;
        goto error_exit;
    }

    if (!VirtualProtectEx(injector->hProcess, injector->data, page_size, PAGE_READWRITE, &old_protect)) {
        set_errmsg("VirtualProtectEx error: %s", w32strerr(GetLastError()));
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
        remote_call_args_t args;
        wchar_t fullpath[MAX_PATH];
    } data = {0, };
    DWORD pathlen;
    intptr_t retval;
    DWORD last_error;
    int rv;

    pathlen = GetFullPathNameW(path, MAX_PATH, data.fullpath, NULL);
    if (pathlen > MAX_PATH) {
        set_errmsg("too long file path: %S", path);
        return INJERR_FILE_NOT_FOUND;
    }
    if (pathlen == 0) {
        set_errmsg("failed to get the full path: %S", path);
        return INJERR_FILE_NOT_FOUND;
    }
    data.args.func = injector->load_library;
    data.args.arg1 = (size_t)injector->data + sizeof(remote_call_args_t);

    rv = remote_call(injector, &data.args, sizeof(data), &retval, &last_error);
    if (rv != 0) {
        return rv;
    }
    if (retval == 0) {
        set_errmsg("LoadLibrary in the target process failed: %s", w32strerr(last_error));
        return INJERR_ERROR_IN_TARGET;
    }
    if (handle != NULL) {
        *handle = (void*)retval;
    }
    return 0;
}

int injector_uninject(injector_t *injector, void *handle)
{
    remote_call_args_t args;
    DWORD pathlen;
    size_t retval;
    DWORD last_error;
    int rv;

    args.func = injector->free_library;
    args.arg1 = (size_t)handle;

    rv = remote_call(injector, &args, sizeof(args), &retval, &last_error);
    if (rv != 0) {
        return rv;
    }
    if ((BOOL)retval) {
        return 0;
    } else {
        set_errmsg("FreeLibrary in the target process failed: %s", w32strerr(last_error));
        return INJERR_ERROR_IN_TARGET;
    }
}

int injector_detach(injector_t *injector)
{
    if (injector->code != NULL) {
        VirtualFreeEx(injector->hProcess, injector->code, 0, MEM_RELEASE);
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

int injector_remote_func_addr(injector_t *injector, void *handle, const char* name, size_t *func_addr_out)
{
    struct {
        remote_call_args_t args;
        char name[512];
    } data = {0, };
    intptr_t retval;
    DWORD last_error;
    int rv;

    if (strlen(name) >= sizeof(data.name)) {
        set_errmsg("too long function name: %s", name);
        return INJERR_FUNCTION_MISSING;
    }

    data.args.func = injector->get_proc_address;
    data.args.arg1 = (size_t)handle;
    data.args.arg2 = (size_t)injector->data + sizeof(remote_call_args_t);
    strncpy(data.name, name, sizeof(data.name));
    rv = remote_call(injector, &data.args, sizeof(data), &retval, &last_error);
    if (rv != 0) {
        return rv;
    }
    if (retval == 0) {
        set_errmsg("GetProcAddress in the target process failed: %s", w32strerr(last_error));
        return INJERR_ERROR_IN_TARGET;
    }
    *func_addr_out = (size_t)retval;
    return 0;
}

int injector_remote_call(injector_t *injector, intptr_t *retval, size_t func_addr, ...)
{
    va_list ap;
    int rv;

    va_start(ap, func_addr);
    rv = injector_remote_vcall(injector, retval, func_addr, ap);
    va_end(ap);
    return rv;
}

int injector_remote_vcall(injector_t *injector, intptr_t *retval, size_t func_addr, va_list ap)
{
    remote_call_args_t args = {0,};

    args.func = func_addr;
    args.arg1 = va_arg(ap, size_t);
    args.arg2 = va_arg(ap, size_t);
    args.arg3 = va_arg(ap, size_t);
    args.arg4 = va_arg(ap, size_t);
    args.arg5 = va_arg(ap, size_t);
    args.arg6 = va_arg(ap, size_t);
    return remote_call(injector, &args, sizeof(args), retval, NULL);
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

static USHORT process_arch(HANDLE hProcess)
{
    PROCESS_MACHINE_INFORMATION pmi;
    if (GetProcessInformation(hProcess, ProcessMachineTypeInfo, &pmi, sizeof(pmi))) {
        // Windows 11
        return pmi.ProcessMachine;
    }
    USHORT process_machine;
    USHORT native_machine;
    if (IsWow64Process2(hProcess, &process_machine, &native_machine)) {
        // Windows 10
        if (process_machine != IMAGE_FILE_MACHINE_UNKNOWN) {
            return process_machine;
        } else {
            return native_machine;
        }
    }
    /* Windows 8.1 or earlier */
    /* arch will be either x86 or x64. */
#if defined(_M_AMD64) || defined(_M_IX86)
    BOOL is_wow64_proc;
#if defined(_M_IX86)
    if (IsWow64Process(GetCurrentProcess(), &is_wow64_proc) && !is_wow64_proc) {
        // Run on 32-bit Windows
        return IMAGE_FILE_MACHINE_I386;
    }
#endif
    if (IsWow64Process(hProcess, &is_wow64_proc)) {
        return is_wow64_proc ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64;
    }
#endif
    return IMAGE_FILE_MACHINE_UNKNOWN;
}

static const char *arch_name(USHORT arch)
{
    switch (arch) {
    case IMAGE_FILE_MACHINE_AMD64:
        return "x64";
    case IMAGE_FILE_MACHINE_ARM64:
        return "arm64";
    case IMAGE_FILE_MACHINE_ARMNT:
        return "arm";
    case IMAGE_FILE_MACHINE_I386:
        return "x86";
    default:
        return "unknown";
    }
}
