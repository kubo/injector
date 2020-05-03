#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#define sleep(secs) Sleep(1000 * (secs))
#else
#include <unistd.h>
#endif

int exit_value = 0;

int main()
{
    sleep(4);
    return exit_value;
}
