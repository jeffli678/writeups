#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#pragma pack(1) 
#define N 32

typedef struct
{
    unsigned char opCode;
    uint32_t operand;
}instr;

instr code[]  __attribute__ ((section (".x86"))) = {
    #include "code.h"
    {0x0f, 0x9090d094},         
    // 00201043  0f94d0             sete    al  {0x1}
    // 00201046  90                 nop     
    // 00201047  90                 nop     
    {0xc3, 0}
    // 00201048  c3                 retn     {__return_addr}
};

int main()
{
    // read the input
    int input = 0;
    int unused = scanf("%d", &input);
    // modify the code according to the user input
    for(int i = 0; i < N; i ++)
    {
        bool bit = input & 1;
        input >>= 1;
        if (bit)
        {
            // add eax, imm32
            code[i + 1].opCode = 0x05;
        }
        else
        {
            // sub eax, imm32
            code[i + 1].opCode = 0x2d;
        }
    }
    // set page to executable
    void *page =
     (void *) ((unsigned long) (&code) &
        ~(getpagesize() - 1));
    mprotect(page, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC);

    // call the code and check result
    bool (*func_ptr)() = (void*)&code;
    if (func_ptr())
    {
        printf("Well done!\n");
    }
    else
    {
        printf("Try again!\n");
    }
}