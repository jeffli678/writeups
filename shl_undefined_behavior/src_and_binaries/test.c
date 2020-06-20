#include <stdio.h>
#include <inttypes.h>

int main()
{
    int n = 64;
    uint64_t ret = (1UL << n) - 1;
    printf("0x%lx\n", ret);
}