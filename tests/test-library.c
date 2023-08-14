#define INCR_ON_INJECTION 13
#define INCR_ON_UNINJECTION 17

#include <stdint.h>

#ifdef _WIN32
#include <windows.h>

intptr_t __declspec(dllexport) sum_integers(intptr_t a1, intptr_t a2, intptr_t a3, intptr_t a4, intptr_t a5, intptr_t a6);

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    HMODULE hMod;
    static int *exit_value_addr;

    switch (reason) {
    case DLL_PROCESS_ATTACH:
        hMod = GetModuleHandle(NULL);
        exit_value_addr = (int *)GetProcAddress(hMod, "exit_value");
        if (exit_value_addr != NULL) {
            *exit_value_addr += INCR_ON_INJECTION;
        } else {
            return FALSE;
        }
        break;
    case DLL_PROCESS_DETACH:
        *exit_value_addr += INCR_ON_UNINJECTION;
        break;
    }
    return TRUE;
}
#elif __APPLE__
#include <dlfcn.h>
static int *exit_value_addr;

__attribute__((constructor))
void init()
{
	exit_value_addr = dlsym(RTLD_DEFAULT, "exit_value");
    *exit_value_addr += INCR_ON_INJECTION;
}

__attribute__((destructor))
void fini()
{
     *exit_value_addr += INCR_ON_UNINJECTION;
}
#else //linux
extern int exit_value;

__attribute__((constructor))
void init()
{
    exit_value += INCR_ON_INJECTION;
}

__attribute__((destructor))
void fini()
{
    exit_value += INCR_ON_UNINJECTION;
}
#endif

intptr_t sum_integers(intptr_t a1, intptr_t a2, intptr_t a3, intptr_t a4, intptr_t a5, intptr_t a6)
{
    return a1 + a2 + a3 + a4 + a5 + a6;
}
