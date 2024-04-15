typedef struct{
    uint32_t u32UsetCmd;
    uint32_t u32InputBuffer;
    uint32_t u32InputSize;
    uint32_t u32OutputBuffer;
    uint32_t u32OutputSize;
} ST_UserDataStruct;

// command ID define (or enum)
//#define USER_CMD_SHA256    0x0
//#define USER_CMD_SHA384    0x1
//#define USER_CMD_SHA512    0x2
typedef enum{
    USER_CMD_HASH_SHA256,
    USER_CMD_HASH_SHA384,
    USER_CMD_HASH_SHA512,
} user_cmd_id_e;

void user_app_execute(uint32_t u32Address, uint32_t u32Size);