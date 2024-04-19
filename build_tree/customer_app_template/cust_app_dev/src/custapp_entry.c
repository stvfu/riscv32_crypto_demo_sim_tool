#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <custapp.h>
#include <custapp_module_sample.h>
#include <custapp_module_test1.h>
#include <custapp_module_test2.h>
#include <custapp_module_test3.h>

void custapp_execute(uint32_t u32Address, uint32_t u32Size)
{
    ST_HpseReqData stHpseReqData;
    memcpy((void *)&stHpseReqData, (const void *)u32Address, (size_t)u32Size);

  // parser module ID
    E_Custapp_Module eModule = (E_Custapp_Module)stHpseReqData.u32Module;
    switch(eModule)
    {
        case CUSTAPP_MODULE_SAMPLE:
            custapp_module_sample_execute(u32Address, u32Size);
            break;

        case CUSTAPP_MODULE_TEST1:
            custapp_module_test1_execute(u32Address, u32Size);
            break;

	case CUSTAPP_MODULE_TEST2:
            custapp_module_test2_execute(u32Address, u32Size);
            break;

        case CUSTAPP_MODULE_TEST3:
            custapp_module_test3_execute(u32Address, u32Size);
            break;

        default:
            printf("Module ID not found!\n");
            break;
    }
}
