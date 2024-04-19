typedef enum{
    E_MODULE_SAMPLE_CMD_ID_SHA256,
    E_MODULE_SAMPLE_CMD_ID_SHA384,
    E_MODULE_SAMPLE_CMD_ID_SHA512,
} E_Custapp_Module_Sample_CmdId;

void custapp_module_sample_execute(uint32_t u32Address, uint32_t u32Size);