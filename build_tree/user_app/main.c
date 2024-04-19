#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <user_app.h>
#include <customization_wrapper.h>

static void _DUMP(int length, char *Adr)
{
    int i;
    for(i=0;i<length;i++)
    {
        if(i % 16 == 0)
        {
                printf("\n0x%.4X: ",i + (int)Adr);
        }

        if(i % 8 == 0)
            printf(" ");

        printf("%.2X ",(int)Adr[i]);
    }
    printf("\n\n");
}

int main(void)
{
    // test pattern
    char au8Data[10] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,  0x38, 0x39};
    char au8HashValue[32] = {0};

    // set data
    ST_UserDataStruct stUserDataStruct = {0};
    stUserDataStruct.u32UsetCmd      = (uint32_t)USER_CMD_HASH_SHA256;
    stUserDataStruct.u32InputBuffer  = (uint32_t)au8Data;
    stUserDataStruct.u32InputSize    = (uint32_t)(sizeof(au8Data));
    stUserDataStruct.u32OutputBuffer = (uint32_t)au8HashValue;
    stUserDataStruct.u32OutputSize   = (uint32_t)(sizeof(au8Data));

    // call service
    user_app_execute((uint32_t)(&stUserDataStruct), (uint32_t)(sizeof(stUserDataStruct)));

    // check result
    printf("SHA256 test\n");
    printf("input data\n");
    _DUMP(10, (char *)stUserDataStruct.u32InputBuffer);
    printf("hash value\n");
    _DUMP(32, (char *)stUserDataStruct.u32OutputBuffer);
}
