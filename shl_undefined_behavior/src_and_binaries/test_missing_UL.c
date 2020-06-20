#include <stdio.h>
#include <inttypes.h>

int main()
{
    int n = 48;
    uint64_t ret = (1 << n) - 1;
    printf("0x%lx\n", ret);
}