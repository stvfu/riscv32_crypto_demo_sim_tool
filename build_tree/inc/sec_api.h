typedef enum {
    ENUM_MBEDTLS,
    ENUM_LIBTOM
} CryptoLib;

void sec_GenRandomBuffer(char *out_buf, int size, CryptoLib eLibSetting);
