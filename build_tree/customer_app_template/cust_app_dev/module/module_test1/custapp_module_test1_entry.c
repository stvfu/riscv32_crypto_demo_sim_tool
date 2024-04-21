#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <customization_wrapper.h>
#include <custapp.h>
#include <custapp_module_test1.h>

void custapp_module_test1_execute(uint32_t u32Address, uint32_t u32Size)
{
    ST_CustappReqData stCustappReqData;
    memcpy((void *)&stCustappReqData, (const void *)u32Address, (size_t)u32Size);

    printf("module %d entry:\n",(int)stCustappReqData.u32Module);

    // parser
    E_Custapp_Module_Test1_CmdId eCmdId = (E_Custapp_Module_Test1_CmdId)stCustappReqData.u32CustappCmd;
    uint32_t u32InputBuffer= stCustappReqData.u32InputBuffer;
    uint32_t u32InputSize= stCustappReqData.u32InputSize;
    uint32_t u32OutputBuffer= stCustappReqData.u32OutputBuffer;
    uint32_t u32OutputSize= stCustappReqData.u32OutputSize;

    switch(eCmdId) // switch case
    {

        case E_MODULE_TEST1_CMD_ID_SHA256:
            customization_hash_sha256((uint32_t*)u32InputBuffer,
                            (uint32_t*)u32OutputBuffer,
                            u32InputSize);
            break;

        case E_MODULE_TEST1_CMD_ID_SHA384:
            customization_hash_sha384((uint32_t*)u32InputBuffer,
                            (uint32_t*)u32OutputBuffer,
                            u32InputSize);
            break;

        default:
            printf("Command ID not found!\n");
            break;
    }
}

