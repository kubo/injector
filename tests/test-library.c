#ifdef _WIN32
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    HMODULE hMod;
    int *exit_value_addr;

    switch (reason) {
    case DLL_PROCESS_ATTACH:
        hMod = GetModuleHandle(NULL);
        exit_value_addr = (int *)GetProcAddress(hMod, "exit_value");
        if (exit_value_addr != NULL) {
            *exit_value_addr = 123;
        } else {
            return FALSE;
        }
        break;
    }
    return TRUE;
}
#else
extern int exit_value;

__attribute__((constructor))
void init()
{
    exit_value = 123;
}
#endif
