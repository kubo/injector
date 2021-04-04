#define INCR_ON_INJECTION 13
#define INCR_ON_UNINJECTION 17

#ifdef _WIN32
#include <windows.h>

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
#else
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
