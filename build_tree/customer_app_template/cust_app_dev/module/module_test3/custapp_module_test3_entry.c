#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <customization_wrapper.h>
#include <custapp.h>
#include <custapp_module_test3.h>

void custapp_module_test3_execute(uint32_t u32Address, uint32_t u32Size)
{
    ST_HpseReqData stHpseReqData;
    memcpy((void *)&stHpseReqData, (const void *)u32Address, (size_t)u32Size);

    printf("module %d entry:\n",(int)stHpseReqData.u32Module);

    // parser
    E_Custapp_Module_Test3_CmdId eCmdId = (E_Custapp_Module_Test3_CmdId)stHpseReqData.u32HpseCmd;
    uint32_t u32InputBuffer= stHpseReqData.u32InputBuffer;
    uint32_t u32InputSize= stHpseReqData.u32InputSize;
    uint32_t u32OutputBuffer= stHpseReqData.u32OutputBuffer;
    uint32_t u32OutputSize= stHpseReqData.u32OutputSize;

    switch(eCmdId) // switch case
    {

        case E_MODULE_TEST3_CMD_ID_SHA256:
            customization_hash_sha256((uint32_t*)u32InputBuffer,
                            (uint32_t*)u32OutputBuffer,
                            u32InputSize);
            break;

        case E_MODULE_TEST3_CMD_ID_SHA384:
            customization_hash_sha384((uint32_t*)u32InputBuffer,
                            (uint32_t*)u32OutputBuffer,
                            u32InputSize);
            break;

        default:
            printf("Command ID not found!\n");
            break;
    }
}

