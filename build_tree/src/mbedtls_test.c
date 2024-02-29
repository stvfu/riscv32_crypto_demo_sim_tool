#include <stdio.h> // for printf
#include <string.h> // for memset

// for hash related test
#include "mbedtls/md5.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

// for aes related test
#include "mbedtls/aes.h"

void DUMP_1(int length, char *Adr)
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

static void mbedtls_test_sha(void)
{
    int counter = 0;
    char str[] = "Hello, world!";
    unsigned char digest[64];

    printf("\n  mbedtls test : MD5\n");
    mbedtls_md5((unsigned char *)str, 13, digest);
    DUMP_1(16, (char *)digest);

    printf("\n  mbedtls test : SHA1\n");
    mbedtls_sha1((unsigned char *)str, 13, digest);
    DUMP_1(20, (char *)digest);

    printf("\n  mbedtls test : SHA256\n");
    mbedtls_sha256((unsigned char *)str, 13, digest, 0);
    DUMP_1(32, (char *)digest);

    printf("\n  mbedtls test : SHA512\n");
    mbedtls_sha512((unsigned char *)str, 13, digest, 0);
    DUMP_1(64, (char *)digest);
    return;
}

static void mbedtls_test_aes_cbc(void)
{
    #define TEST_BUFFER_SIZE 64
    #define IV_DATA "1234567812345678"

    unsigned char buf[TEST_BUFFER_SIZE] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    unsigned char encrypt_buf[TEST_BUFFER_SIZE] = { 0 };

    char secretKey[16] = "1234567812345678";
    unsigned char iv[16] = IV_DATA;

    int len = ((int)strlen((const char *)buf) / 16 ) * 16;
    // init aes context
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    // set key
    mbedtls_aes_setkey_enc(&ctx, (const unsigned char *)secretKey, 128);

    printf("\n test buf:");
    DUMP_1(TEST_BUFFER_SIZE, (char *)buf);
    printf("\n key buf:");
    DUMP_1(16, (char *)secretKey);
    printf("\n iv buf:");
    DUMP_1(16, (char *)iv);

    // do encrypt
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, (size_t)len, iv, (const unsigned char *)buf, encrypt_buf);
    printf("\n enceypted buf:");
    DUMP_1(TEST_BUFFER_SIZE, (char *)encrypt_buf);

    // reset buffer
    memset(buf,0,sizeof(buf));
    memset(iv,0,16);
    strcpy((char *)iv, (const char *)IV_DATA);

    // do decrypt
    mbedtls_aes_setkey_dec(&ctx, (const unsigned char *)secretKey, 128);
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, (size_t)len, iv, (const unsigned char *)encrypt_buf, buf);

    printf("\ndecrypted to orig buf:");
    DUMP_1(TEST_BUFFER_SIZE, (char *)buf);


    printf("online tool verify: https://www.lddgo.net/en/encrypt/aes\n");
    mbedtls_aes_free(&ctx);
}	

int mbedtls_test(void) {
    printf("\n  \033[33mmbedtls aes test\033[0m\n");
    mbedtls_test_aes_cbc();

    printf("\n  \033[33mmbedtls sha test\033[0m\n");
    mbedtls_test_sha();

    printf("\n  \033[33mmbedtls random test\033[0m\n");

    printf("\n  \033[33mmbedtls rsa test\033[0m\n");

    return 0;
}

