typedef enum{
    E_MODULE_TEST6_CMD_ID_SHA256,
    E_MODULE_TEST6_CMD_ID_SHA384,
    E_MODULE_TEST6_CMD_ID_SHA512,
} E_Custapp_Module_Test6_CmdId;

void custapp_module_test6_execute(uint32_t u32Address, uint32_t u32Size);