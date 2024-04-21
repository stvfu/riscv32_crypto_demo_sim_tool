typedef struct{
    uint32_t u32Module;
    uint32_t u32CustappCmd;
    uint32_t u32InputBuffer;
    uint32_t u32InputSize;
    uint32_t u32OutputBuffer;
    uint32_t u32OutputSize;
} ST_CustappReqData;

typedef enum{
    CUSTAPP_MODULE_SAMPLE,
    CUSTAPP_MODULE_TEST1,
    CUSTAPP_MODULE_TEST2,
    CUSTAPP_MODULE_TEST3,
    CUSTAPP_MODULE_TEST4,
    CUSTAPP_MODULE_TEST5,
    CUSTAPP_MODULE_TEST6,
} E_Custapp_Module;


void custapp_execute(uint32_t u32Address, uint32_t u32Size);
