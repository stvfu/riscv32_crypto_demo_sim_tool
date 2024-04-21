#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <customization_wrapper.h>

#include <custapp.h>
#include <custapp_module_test1.h>

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

void test_custapp_module_test1(void)
{
    // test pattern
    char au8Data[10] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,  0x38, 0x39};
    char au8HashValue[32] = {0};

    // set data
    ST_CustappReqData stCustappReqData = {0};
    stCustappReqData.u32Module       = (uint32_t)CUSTAPP_MODULE_TEST1;
    stCustappReqData.u32CustappCmd      = (uint32_t)E_MODULE_TEST1_CMD_ID_SHA256;
    stCustappReqData.u32InputBuffer  = (uint32_t)au8Data;
    stCustappReqData.u32InputSize    = (uint32_t)(sizeof(au8Data));
    stCustappReqData.u32OutputBuffer = (uint32_t)au8HashValue;
    stCustappReqData.u32OutputSize   = (uint32_t)(sizeof(au8HashValue));

    // call service
    custapp_execute((uint32_t)(&stCustappReqData), (uint32_t)(sizeof(stCustappReqData)));

    // check result
    printf("SHA256 test\n");
    printf("input data\n");
    _DUMP(10, (char *)stCustappReqData.u32InputBuffer);
    printf("hash value\n");
    _DUMP(32, (char *)stCustappReqData.u32OutputBuffer);
}
