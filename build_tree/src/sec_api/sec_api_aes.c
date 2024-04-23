#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <sec_api.h>
#include <tomcrypt.h>

#include "mbedtls/cmac.h"
#include "mbedtls/ctr_drbg.h"

#define _SEC_TRACE_IN  printf("[%s][%d] IN\n", __func__,__LINE__);
#define _SEC_TRACE_OUT printf("[%s][%d] OUT\n", __func__,__LINE__);

static void _DUMP_(int length, char *Adr)
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

// AES
int sec_aes_ecb_enc(int key_size_in_bytes,
                    char *add_key,
                    char *add_src,
                    char *add_dest,
                    int tr_size_in_bytes)
{
    _SEC_TRACE_IN
    unsigned char au8EcbEncryptRes[16] = {0};
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_dec(&aes_ctx,
                           (const unsigned char *)add_key,
                           (unsigned int)(key_size_in_bytes*8)); // Ex: 16 byte = 128 bit
    mbedtls_aes_crypt_ecb(&aes_ctx,
                          MBEDTLS_AES_ENCRYPT,
                          (const unsigned char *)add_src,
                          au8EcbEncryptRes);
    memcpy((void *)add_dest, (const void *)au8EcbEncryptRes, 16);
    mbedtls_aes_free(&aes_ctx);
    _SEC_TRACE_OUT
    return 0;
}

int sec_aes_ecb_dec(int key_size_in_bytes,
                    char *add_key,
                    char *add_src,
                    char *add_dest,
                    int tr_size_in_bytes)
{
    _SEC_TRACE_IN
    unsigned char au8EcbDecryptRes[16] = {0};
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_dec(&aes_ctx,
                           (const unsigned char *)add_key,
                           (unsigned int)(key_size_in_bytes*8)); // Ex: 16 byte = 128 bit
    mbedtls_aes_crypt_ecb(&aes_ctx,
                          MBEDTLS_AES_DECRYPT,
                          (const unsigned char *)add_src,
                          au8EcbDecryptRes);
    memcpy((void *)add_dest, (const void *)au8EcbDecryptRes, 16);
    mbedtls_aes_free(&aes_ctx);
    _SEC_TRACE_OUT
    return 0;
}

int sec_aes_cbc_enc(int key_size_in_bytes,
                    char *add_key,
                    char *add_iv,
                    char *add_src,
                    char *add_dest,
                    int tr_size_in_bytes)
{
    _SEC_TRACE_IN
    unsigned char au8iv[16] = {0};
    memcpy((void *)au8iv, (const void *)add_iv, 16);

    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_enc(&aes_ctx,
                           (const unsigned char *)add_key,
                           (unsigned int)(key_size_in_bytes*8)); // Ex: 16 byte = 128 bit
    mbedtls_aes_crypt_cbc(&aes_ctx,
                          MBEDTLS_AES_ENCRYPT,
                          (size_t)tr_size_in_bytes,
                          au8iv,
                          (const unsigned char *)add_src,
                          (unsigned char *)add_dest);
    mbedtls_aes_free(&aes_ctx);
    _SEC_TRACE_OUT
    return 0;
}

int sec_aes_cbc_dec(int key_size_in_bytes,
                    char *add_key,
                    char *add_iv,
                    char *add_src,
                    char *add_dest,
                    int tr_size_in_bytes)
{
    _SEC_TRACE_IN
    unsigned char au8iv[16] = {0};
    memcpy((void *)au8iv, (const void *)add_iv, 16);

    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_dec(&aes_ctx,
                           (const unsigned char *)add_key,
                           (unsigned int)(key_size_in_bytes*8)); // Ex: 16 byte = 128 bit
    mbedtls_aes_crypt_cbc(&aes_ctx,
                          MBEDTLS_AES_DECRYPT,
                          (size_t)tr_size_in_bytes,
                          au8iv,
                          (const unsigned char *)add_src,
                          (unsigned char *)add_dest);
    mbedtls_aes_free(&aes_ctx);
    _SEC_TRACE_OUT
    return 0;
}


int sec_aes_ctr_enc(int key_size_in_bytes,
                    char *add_key,
                    char *add_iv,
                    char *add_src,
                    char *add_dest,
                    int tr_size_in_bytes)
{
    _SEC_TRACE_IN
    int idx;
    symmetric_CTR ctr;
    register_cipher(&aes_desc);
    idx = find_cipher("aes");
    ctr_start(idx,
              (const unsigned char *)add_iv,
              (const unsigned char *)add_key,
              key_size_in_bytes,
              0,
              CTR_COUNTER_BIG_ENDIAN,
              &ctr);
    ctr_encrypt((const unsigned char *)add_src,
                (unsigned char *)add_dest,
                (long unsigned int)tr_size_in_bytes,
                &ctr);
    _SEC_TRACE_OUT
    return 0;
}

int sec_aes_ctr_dec(int key_size_in_bytes,
                    char *add_key,
                    char *add_iv,
                    char *add_src,
                    char *add_dest,
                    int tr_size_in_bytes)
{
    _SEC_TRACE_IN
    int idx;
    symmetric_CTR ctr;
    register_cipher(&aes_desc);
    idx = find_cipher("aes");
    ctr_start(idx,
              (const unsigned char *)add_iv,
              (const unsigned char *)add_key,
              key_size_in_bytes,
              0,
              CTR_COUNTER_BIG_ENDIAN,
              &ctr);
    ctr_decrypt((const unsigned char *)add_src,
                (unsigned char *)add_dest,
                (long unsigned int)tr_size_in_bytes,
                &ctr);
    _SEC_TRACE_OUT
    return 0;
}


int sec_aes_cmac(int key_size_in_bytes,
                 char *add_key,
                 char *add_src,
                 char *add_dest,
                 int tr_size_in_bytes)
{
    _SEC_TRACE_IN
    unsigned char au8CmacRes[16] = {0};
    mbedtls_aes_cmac_prf_128((const unsigned char *)add_key,
                             (size_t)key_size_in_bytes,
                             (const unsigned char *)add_src,
                             (size_t)tr_size_in_bytes,
                             au8CmacRes);
    memcpy((void *)add_dest, (const void *)au8CmacRes, 16);
    _SEC_TRACE_OUT
    return 0;
}

