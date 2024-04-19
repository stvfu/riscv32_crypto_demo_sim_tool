#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <user_app.h>
#include <customization_wrapper.h>

void user_app_execute(uint32_t u32Address, uint32_t u32Size)
{
    ST_UserDataStruct stUserDataStruct;
    memcpy((void *)&stUserDataStruct, (const void *)u32Address, (size_t)u32Size);
    // parser
    uint32_t u32UsetCmd = (user_cmd_id_e)stUserDataStruct.u32UsetCmd;
    uint32_t u32InputBuffer= stUserDataStruct.u32InputBuffer;
    uint32_t u32InputSize= stUserDataStruct.u32InputSize;
    uint32_t u32OutputBuffer= stUserDataStruct.u32OutputBuffer;
    uint32_t u32OutputSize= stUserDataStruct.u32OutputSize;

    switch(u32UsetCmd)    // switch case
    {
        case USER_CMD_HASH_SHA256:
            customization_hash_sha256((uint32_t*)u32InputBuffer, 
                            (uint32_t*)u32OutputBuffer, 
                            u32InputSize);
            break;
    
        case USER_CMD_HASH_SHA384:
            customization_hash_sha384((uint32_t*)u32InputBuffer, 
                            (uint32_t*)u32OutputBuffer, 
                            u32InputSize);
            break;
        default:
            printf("Command ID not found!\n");
            break;

    }
}

