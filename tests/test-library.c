#include <stdio.h>
#include <stdlib.h>

extern int exit_value;

__attribute__((constructor))
void init()
{
    exit_value = 123;
}
