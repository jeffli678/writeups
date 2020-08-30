//simple.c
//gcc -Wl,-z,lazy -o simple simple.c
#include<stdio.h>
// #include<elf.h>

int main()
{
        // Elf32_Dyn s;
        puts("0xdeadbeef\n");
        getchar();
        return 0;
}