#include <stdio.h>

#include <add.h>
#include <libtom_test.h>
#include <mbedtls_test.h>
#include <sec_api.h>

typedef struct MENU{
    char *NAME;
    void (*func_ptr)(void);
}MENU;

#define _TEST_SUITE_TRACE_IN  printf("[%s][%d] Test case start\n", __func__,__LINE__);
#define _TEST_SUITE_TRACE_OUT printf("[%s][%d] Test case end\n", __func__,__LINE__);

#include "test_case.inc"

static void _DUMP(int length, char *Adr)
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

////////////////////////////////////////////////////////////////////////
// common api
////////////////////////////////////////////////////////////////////////
static void test(void)
{
    printf("Test case template\n");
}

static void test_printf(void)
{
    printf("Hello world!!\n");
}

static void test_lib(void)
{
    printf("static lib test\n");
    printf("  add test: 2+3 = %d\n",add_test(2,3));
}

static void test_libtom(void)
{
    libtom_test();
}

static void test_mebtls(void)
{
    mbedtls_test();
}

////////////////////////////////////////////////////////////////////////
// random related api
////////////////////////////////////////////////////////////////////////
static void test_random(void)
{
    char random_buffer[32] = {0};
    sec_generate_random_buffer(random_buffer, 32);
}

////////////////////////////////////////////////////////////////////////
// SHA related api
////////////////////////////////////////////////////////////////////////
static void test_sha1(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha1(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(20, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha1.html\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_sha224(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha224(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(28, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha224.html\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_sha256(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha256(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(32, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha256.html\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_sha384(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha384(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(48, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha384.html\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_sha512(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha512(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(64, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha512.html\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_sha512_224(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha512_224(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(28, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha512_224.html\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_sha512_256(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha512_256(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(32, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha512_256.html\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_sha3_sha224(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha3_sha224(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(28, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha3_sha224.html\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_sha3_sha256(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha3_sha256(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(32, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha3_sha256.html\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_sha3_sha384(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha3_sha384(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(48, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha3_sha384.html\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_sha3_sha512(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha3_sha512(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(64, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha3_sha512.html\n");
    _TEST_SUITE_TRACE_OUT
}

////////////////////////////////////////////////////////////////////////
// AES related API
////////////////////////////////////////////////////////////////////////
static void test_aes_ecb_encrypt(void)
{
    _TEST_SUITE_TRACE_IN
    char au8ClearData[16] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    char au8Key[16] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                       0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    char au8EncryptedData[16] = {0};

    sec_aes_ecb_enc(16, au8Key, au8ClearData, au8EncryptedData, 16);

    // debug log
    printf("Clear data(HEX), size = %d\n", sizeof(au8ClearData));
    _DUMP(sizeof(au8ClearData), au8ClearData);
    printf("Key data(HEX), size = %d\n", sizeof(au8Key));
    _DUMP(sizeof(au8Key), au8Key);
    printf("Encrypted data(HEX), size = %d\n", sizeof(au8EncryptedData));
    _DUMP(sizeof(au8EncryptedData), au8EncryptedData);
    printf("you can check result in online tool:\n");
    printf("https://www.lddgo.net/en/encrypt/aes\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_aes_ecb_decrypt(void)
{
    _TEST_SUITE_TRACE_IN
    char au8ClearData[16] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    char au8Key[16] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                       0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    char au8DecryptedData[16] = {0};

    sec_aes_ecb_dec(16, au8Key, au8ClearData, au8DecryptedData, 16);

    // debug log
    printf("Clear data(HEX), size = %d\n", sizeof(au8ClearData));
    _DUMP(sizeof(au8ClearData), au8ClearData);
    printf("Key data(HEX), size = %d\n", sizeof(au8Key));
    _DUMP(sizeof(au8Key), au8Key);
    printf("Decrypted data(HEX), size = %d\n", sizeof(au8DecryptedData));
    _DUMP(sizeof(au8DecryptedData), au8DecryptedData);
    printf("you can check result in online tool:\n");
    printf("https://www.lddgo.net/en/encrypt/aes\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_aes_cbc_encrypt(void)
{
    _TEST_SUITE_TRACE_IN
    char au8ClearData[64] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    char au8Key[16] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                       0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    char au8Iv[16] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                      0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    char au8EncryptedData[64] = {0};

    sec_aes_cbc_enc(16, au8Key, au8Iv, au8ClearData, au8EncryptedData, sizeof(au8ClearData));

    // debug log
    printf("Clear data(HEX), size = %d\n", sizeof(au8ClearData));
    _DUMP(sizeof(au8ClearData), au8ClearData);
    printf("Key data(HEX), size = %d\n", sizeof(au8Key));
    _DUMP(sizeof(au8Key), au8Key);
    printf("Iv data(HEX), size = %d\n", sizeof(au8Iv));
    _DUMP(sizeof(au8Iv), au8Iv);
    printf("Ecrypted data(HEX), size = %d\n", sizeof(au8EncryptedData));
    _DUMP(sizeof(au8EncryptedData), au8EncryptedData);
    printf("you can check result in online tool:\n");
    printf("https://www.lddgo.net/en/encrypt/aes\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_aes_cbc_decrypt(void)
{
    _TEST_SUITE_TRACE_IN
    char au8ClearData[64] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    char au8Key[16] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                       0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    char au8Iv[16] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                      0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    char au8DecryptedData[64] = {0};
    sec_aes_cbc_dec(16, au8Key, au8Iv, au8ClearData, au8DecryptedData, sizeof(au8ClearData));

    // debug log
    printf("Clear data(HEX), size = %d\n", sizeof(au8ClearData));
    _DUMP(sizeof(au8ClearData), au8ClearData);
    printf("Key data(HEX), size = %d\n", sizeof(au8Key));
    _DUMP(sizeof(au8Key), au8Key);
    printf("Iv data(HEX), size = %d\n", sizeof(au8Iv));
    _DUMP(sizeof(au8Iv), au8Iv);
    printf("Decrypted data(HEX), size = %d\n", sizeof(au8DecryptedData));
    _DUMP(sizeof(au8DecryptedData), au8DecryptedData);
    printf("you can check result in online tool:\n");
    printf("https://www.lddgo.net/en/encrypt/aes\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_aes_ctr_encrypt(void)
{
    _TEST_SUITE_TRACE_IN
    char au8ClearData[64] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    char au8Key[16] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                       0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    char au8Iv[16] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                      0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    char au8EncryptedData[64] = {0};

    sec_aes_ctr_enc(16, au8Key, au8Iv, au8ClearData, au8EncryptedData, sizeof(au8ClearData));

    // debug log
    printf("Clear data(HEX), size = %d\n", sizeof(au8ClearData));
    _DUMP(sizeof(au8ClearData), au8ClearData);
    printf("Key data(HEX), size = %d\n", sizeof(au8Key));
    _DUMP(sizeof(au8Key), au8Key);
    printf("Iv data(HEX), size = %d\n", sizeof(au8Iv));
    _DUMP(sizeof(au8Iv), au8Iv);
    printf("Ecrypted data(HEX), size = %d\n", sizeof(au8EncryptedData));
    _DUMP(sizeof(au8EncryptedData), au8EncryptedData);
    printf("you can check result in online tool:\n");
    printf("https://www.lddgo.net/en/encrypt/aes\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_aes_ctr_decrypt(void)
{
    _TEST_SUITE_TRACE_IN
    char au8ClearData[64] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    char au8Key[16] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                       0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    char au8Iv[16] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                      0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    char au8DecryptedData[64] = {0};

    sec_aes_ctr_dec(16, au8Key, au8Iv, au8ClearData, au8DecryptedData, sizeof(au8ClearData));

    // debug log
    printf("Clear data(HEX), size = %d\n", sizeof(au8ClearData));
    _DUMP(sizeof(au8ClearData), au8ClearData);
    printf("Key data(HEX), size = %d\n", sizeof(au8Key));
    _DUMP(sizeof(au8Key), au8Key);
    printf("Iv data(HEX), size = %d\n", sizeof(au8Iv));
    _DUMP(sizeof(au8Iv), au8Iv);
    printf("Derypted data(HEX), size = %d\n", sizeof(au8DecryptedData));
    _DUMP(sizeof(au8DecryptedData), au8DecryptedData);
    printf("you can check result in online tool:\n");
    printf("https://www.lddgo.net/en/encrypt/aes\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_aes_cmac(void)
{
    _TEST_SUITE_TRACE_IN
    char au8ClearData[64] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    char au8Key[16] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                       0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    char au8Cmac[16] = {0};

    sec_aes_cmac(sizeof(au8Key), au8Key, au8ClearData, au8Cmac, sizeof(au8ClearData));


    // debug log
    printf("Clear data(HEX), size = %d\n", sizeof(au8ClearData));
    _DUMP(sizeof(au8ClearData), au8ClearData);
    printf("Key data(HEX), size = %d\n", sizeof(au8Key));
    _DUMP(sizeof(au8Key), au8Key);
    printf("Cmac(HEX), size = %d\n", sizeof(au8Cmac));
    _DUMP(sizeof(au8Cmac), au8Cmac);

    printf("you can check result in online tool:\n");
    printf("https://artjomb.github.io/cryptojs-extension/\n");
    _TEST_SUITE_TRACE_OUT
}

////////////////////////////////////////////////////////////////////////
// RSA related API
////////////////////////////////////////////////////////////////////////
static void test_rsa_genkey(void)
{
    char n[256]={0};
    char e[3]={0x1, 0x0, 0x01}; // 65537
    char d[256]={0};
    char p[128]={0};
    char q[128]={0};
    char dP[128]={0};
    char dQ[128]={0};
    char qInv[128]={0};

    sec_rsa_generate_key(n, p, q, dP, dQ, qInv, 65537, 2048);
    //sec_GenRsaKey();

    printf("\n N Key\n");
    _DUMP(256, n);
    printf("\n E Key\n");
    _DUMP(3,   e);
    printf("\n P Key\n");
    _DUMP(128, p);
    printf("\n Q Key\n");
    _DUMP(128, q);
    printf("\n dP\n");
    _DUMP(128, dP);
    printf("\n dQ:\n");
    _DUMP(128, dQ);
    printf("\n qInv:\n");
    _DUMP(128, qInv);
}

static void test_rsa_sign(void)
{
    char au8RsaKey_P[128] = {
        0xe7, 0x9a, 0x37, 0x31, 0x82, 0xbf, 0xaa, 0x72, 0x2e, 0xb0, 0x35, 0xf7, 0x72, 0xad, 0x2a, 0x94,
        0x64, 0xbd, 0x84, 0x2d, 0xe5, 0x94, 0x32, 0xc1, 0x8b, 0xba, 0xb3, 0xa7, 0xdf, 0xea, 0xe3, 0x18,
        0xc9, 0xb9, 0x15, 0xee, 0x48, 0x78, 0x61, 0xab, 0x66, 0x5a, 0x40, 0xbd, 0x6c, 0xda, 0x56, 0x01,
        0x52, 0x57, 0x8e, 0x85, 0x79, 0x01, 0x6c, 0x92, 0x9d, 0xf9, 0x9f, 0xea, 0x05, 0xb4, 0xd6, 0x4e,
        0xfc, 0xa1, 0xd5, 0x43, 0x85, 0x0b, 0xc8, 0x16, 0x4b, 0x40, 0xd7, 0x1e, 0xd7, 0xf3, 0xfa, 0x41,
        0x05, 0xdf, 0x0f, 0xb9, 0xb9, 0xad, 0x2a, 0x18, 0xce, 0x18, 0x2c, 0x8a, 0x4f, 0x4f, 0x97, 0x5b,
        0xea, 0x9a, 0xa0, 0xb9, 0xa1, 0x43, 0x8a, 0x27, 0xa2, 0x8e, 0x97, 0xac, 0x83, 0x30, 0xef, 0x37,
        0x38, 0x34, 0x14, 0xd1, 0xbd, 0x64, 0x60, 0x7d, 0x69, 0x79, 0xac, 0x05, 0x04, 0x24, 0xfd, 0x17
    };

    char au8RsaKey_Q[128] = {
        0xc6, 0x74, 0x9c, 0xbb, 0x0d, 0xb8, 0xc5, 0xa1, 0x77, 0x67, 0x2d, 0x47, 0x28, 0xa8, 0xb2, 0x23,
        0x92, 0xb2, 0xfc, 0x4d, 0x3b, 0x83, 0x61, 0xd5, 0xc0, 0xd5, 0x05, 0x5a, 0x1b, 0x4e, 0x46, 0xd8,
        0x21, 0xf7, 0x57, 0xc2, 0x4e, 0xef, 0x2a, 0x51, 0xc5, 0x61, 0x94, 0x1b, 0x93, 0xb3, 0xac, 0xe7,
        0x34, 0x00, 0x74, 0xc0, 0x58, 0xc9, 0xbb, 0x48, 0xe7, 0xe7, 0x41, 0x4f, 0x42, 0xc4, 0x1d, 0xa4,
        0xcc, 0xcb, 0x5c, 0x2b, 0xa9, 0x1d, 0xeb, 0x30, 0xc5, 0x86, 0xb7, 0xfb, 0x18, 0xaf, 0x12, 0xa5,
        0x29, 0x95, 0x59, 0x2a, 0xd1, 0x39, 0xd3, 0xbe, 0x42, 0x9a, 0xdd, 0x65, 0x47, 0xe0, 0x44, 0xbe,
        0xce, 0xda, 0xf3, 0x1f, 0xa3, 0xb3, 0x94, 0x21, 0xe2, 0x4e, 0xe0, 0x34, 0xfb, 0xf3, 0x67, 0xd1,
        0x1f, 0x6b, 0x8f, 0x88, 0xee, 0x48, 0x3d, 0x16, 0x3b, 0x43, 0x1e, 0x16, 0x54, 0xad, 0x3e, 0x89
    };

    char au8RsaKey_E[3] ={0x00, 0x00, 0x03};

    char au8Message[20] = {0x8E, 0xB2, 0x08, 0xF7, 0xE0, 0x5D, 0x98, 0x7A, 0x9B, 0x04, 0x4A, 0x8E, 0x98, 0xC6, 0xB0, 0x87,
                           0xF1, 0x5A, 0x0B, 0xFC};

    char au8Signature[256] = {0};
    sec_rsa_sign((char*)au8RsaKey_E,
                 (char*)au8RsaKey_P,
                 (char*)au8RsaKey_Q,
                 (char*)NULL,
                 (char*)NULL,
                 (char*)NULL,
                 (int)(sizeof(au8RsaKey_P)*2),
                 (int)(sizeof(au8RsaKey_E)),
                 (int)(sizeof(au8RsaKey_P)),
                 (int)4,
                 (char *)au8Message,
                 (int)(sizeof(au8Message)),
                 (char *)au8Signature,
                 (int)(sizeof(au8Signature)));

    printf("\n Sig:\n");
    _DUMP(256, au8Signature);
}

static void test_rsa_verify(void)
{
    char au8RsaKey_N[256] ={0xb3, 0x8a, 0xc6, 0x5c, 0x81, 0x41, 0xf7, 0xf5, 0xc9, 0x6e, 0x14, 0x47, 0x0e, 0x85, 0x19, 0x36,
                            0xa6, 0x7b, 0xf9, 0x4c, 0xc6, 0x82, 0x1a, 0x39, 0xac, 0x12, 0xc0, 0x5f, 0x7c, 0x0b, 0x06, 0xd9,
                            0xe6, 0xdd, 0xba, 0x22, 0x24, 0x70, 0x3b, 0x02, 0xe2, 0x5f, 0x31, 0x45, 0x2f, 0x9c, 0x4a, 0x84,
                            0x17, 0xb6, 0x26, 0x75, 0xfd, 0xc6, 0xdf, 0x46, 0xb9, 0x48, 0x13, 0xbc, 0x7b, 0x97, 0x69, 0xa8,
                            0x92, 0xc4, 0x82, 0xb8, 0x30, 0xbf, 0xe0, 0xad, 0x42, 0xe4, 0x66, 0x68, 0xac, 0xe6, 0x89, 0x03,
                            0x61, 0x7f, 0xaf, 0x66, 0x81, 0xf4, 0xba, 0xbf, 0x1c, 0xc8, 0xe4, 0xb0, 0x42, 0x0d, 0x3c, 0x7f,
                            0x61, 0xdc, 0x45, 0x43, 0x4c, 0x6b, 0x54, 0xe2, 0xc3, 0xee, 0x0f, 0xc0, 0x79, 0x08, 0x50, 0x9d,
                            0x79, 0xc9, 0x82, 0x6e, 0x67, 0x3b, 0xf8, 0x36, 0x32, 0x55, 0xad, 0xb0, 0xad, 0xd2, 0x40, 0x10,
                            0x39, 0xa7, 0xbc, 0xd1, 0xb4, 0xec, 0xf0, 0xfb, 0xe6, 0xec, 0x83, 0x69, 0xd2, 0xda, 0x48, 0x6e,
                            0xec, 0x59, 0x55, 0x9d, 0xd1, 0xd5, 0x4c, 0x9b, 0x24, 0x19, 0x09, 0x65, 0xea, 0xfb, 0xda, 0xb2,
                            0x03, 0xb3, 0x52, 0x55, 0x76, 0x52, 0x61, 0xcd, 0x09, 0x09, 0xac, 0xf9, 0x3c, 0x3b, 0x8b, 0x84,
                            0x28, 0xcb, 0xb4, 0x48, 0xde, 0x47, 0x15, 0xd1, 0xb8, 0x13, 0xd0, 0xc9, 0x48, 0x29, 0xc2, 0x29,
                            0x54, 0x3d, 0x39, 0x1c, 0xe0, 0xad, 0xab, 0x53, 0x51, 0xf9, 0x7a, 0x38, 0x10, 0xc1, 0xf7, 0x3d,
                            0x7b, 0x14, 0x58, 0xb9, 0x7d, 0xae, 0xd4, 0x20, 0x9c, 0x50, 0xe1, 0x6d, 0x06, 0x4d, 0x2d, 0x5b,
                            0xfd, 0xa8, 0xc2, 0x38, 0x93, 0xd7, 0x55, 0x22, 0x27, 0x93, 0x14, 0x6d, 0x0a, 0x78, 0xc3, 0xd6,
                            0x4f, 0x35, 0x54, 0x91, 0x41, 0x48, 0x6c, 0x3b, 0x09, 0x61, 0xa7, 0xb4, 0xc1, 0xa2, 0x03, 0x4f
                            };

    char au8RsaKey_E[3] ={0x00, 0x00, 0x03};

    char au8Message[20] = {0x8E, 0xB2, 0x08, 0xF7, 0xE0, 0x5D, 0x98, 0x7A, 0x9B, 0x04, 0x4A, 0x8E, 0x98, 0xC6, 0xB0, 0x87,
                           0xF1, 0x5A, 0x0B, 0xFC};

    char au8Signature[256] = {0xaa, 0x2d, 0x9f, 0x88, 0x33, 0x4d, 0x61, 0xbe, 0xd7, 0x43, 0x17, 0xba, 0x54, 0x9b, 0x14, 0x63,
                              0x60, 0x0a, 0x92, 0x19, 0x80, 0x12, 0x40, 0xcc, 0xa5, 0xc1, 0x1b, 0x9c, 0xdd, 0xa2, 0x93, 0x73,
                              0x17, 0x2a, 0x28, 0x15, 0x13, 0x13, 0xfb, 0x2c, 0xf7, 0x3b, 0xb6, 0x8a, 0xf1, 0x67, 0xe4, 0xec,
                              0x64, 0x5b, 0x6f, 0x06, 0x50, 0x28, 0x80, 0x2a, 0xfb, 0xcf, 0xbc, 0x10, 0xe6, 0xc2, 0xc8, 0x24,
                              0xe3, 0xc4, 0xd5, 0x0c, 0x71, 0x81, 0x19, 0x3b, 0x93, 0x73, 0x48, 0x32, 0x17, 0x0f, 0x0c, 0x5d,
                              0x3d, 0xd9, 0xba, 0x58, 0x08, 0xf0, 0xe2, 0xa5, 0xc1, 0x6b, 0x3d, 0x0d, 0xf9, 0x0d, 0xef, 0xef,
                              0xef, 0x8e, 0x8f, 0xde, 0x59, 0x06, 0x96, 0x2d, 0x42, 0xa2, 0xf0, 0xd6, 0x2d, 0x7f, 0x81, 0x97,
                              0x7f, 0x36, 0x7f, 0x43, 0x6f, 0x10, 0xc8, 0xb1, 0x18, 0x3c, 0xcf, 0x66, 0x76, 0x95, 0x3f, 0x72,
                              0x19, 0x44, 0x59, 0x38, 0xf7, 0x25, 0xd0, 0xcb, 0x62, 0xef, 0xba, 0xbf, 0x09, 0x2d, 0xe5, 0x31,
                              0x64, 0x28, 0x63, 0xb3, 0x81, 0xe2, 0x69, 0x4f, 0x2b, 0xf5, 0x44, 0xff, 0x6a, 0x4f, 0xef, 0xa7,
                              0xb3, 0x7c, 0xdb, 0xf6, 0x29, 0x2d, 0xbe, 0xdc, 0xac, 0xf6, 0xe5, 0x7d, 0x6f, 0x20, 0x6c, 0xe5,
                              0xdf, 0x0f, 0xd2, 0x77, 0x1f, 0x9f, 0x64, 0x81, 0x8f, 0x59, 0xa0, 0xab, 0x7a, 0x5f, 0x00, 0x3b,
                              0x36, 0x8d, 0xc3, 0xeb, 0x51, 0xab, 0x94, 0x09, 0xa0, 0xec, 0x4e, 0x43, 0xf4, 0x52, 0x81, 0xee,
                              0x9a, 0x56, 0x06, 0x64, 0xde, 0x88, 0x96, 0x5a, 0xb2, 0x07, 0xe2, 0x56, 0x30, 0x3d, 0x9d, 0xcb,
                              0x82, 0x33, 0xed, 0x6a, 0xd0, 0xa5, 0xad, 0x7f, 0x81, 0xe2, 0xf8, 0xc7, 0xa1, 0x96, 0xdc, 0x81,
                              0xe2, 0xc8, 0xb6, 0xdd, 0xe8, 0xa7, 0x7f, 0xb6, 0xcf, 0xd1, 0xe5, 0x47, 0x7e, 0xce, 0x9d, 0xf8};
    sec_rsa_verify((char*)au8RsaKey_N,
                   (char*)au8RsaKey_E,
                   (int)(sizeof(au8RsaKey_N)),
                   (int)(sizeof(au8RsaKey_E)),
                   (int)4,
                   (char *)au8Message,
                   (int)(sizeof(au8Message)),
                   (char *)au8Signature,
                   (int)(sizeof(au8Signature)));
}
////////////////////////////////////////////////////////////////////////
// ECC related API
////////////////////////////////////////////////////////////////////////
#include "test_case_ecc.inc"

////////////////////////////////////////////////////////////////////////
// Test case Menu related API
////////////////////////////////////////////////////////////////////////
void __test_suite_message__(void)
{
    printf("\n\n");
    printf("-----------------------------------------------\n");
    printf(" RISC-V crypto test suit\n");
    printf("-----------------------------------------------\n");
    int s32Index;
    int s32MenuNum = sizeof(MENU_TABLE)/sizeof(MENU);
    for(s32Index=0;s32Index<s32MenuNum;s32Index++)
    {
    printf("%2d.  %s\n", s32Index, MENU_TABLE[s32Index].NAME);
    }
    printf(" q.  exit\n");
    printf("-----------------------------------------------\n");
    printf("Please input the selection : \n");

}

void __test_suite__(void)
{
    printf("\n\nEnter RISC-V Crypto Test Sueite\n");

    char u8CharInput;
    int s32Index = 0;
    int s32CharNumber = 0;
    int s32ClearTextIndex = 0;
    int s32MenuNum = sizeof(MENU_TABLE)/sizeof(MENU);

    while(1)
    {
        s32Index = 0;
        s32CharNumber = 0;
        __test_suite_message__();

        // char input
        while(1)
        {
            u8CharInput = (char)getchar();
            //printf("u8CharInput = 0x%x\n", u8CharInput);

            if((u8CharInput >= 0x30)&&(u8CharInput <= 0x39)) // 0~9
            {
                if(s32CharNumber < 2)
                {
                    s32CharNumber++;
                    s32Index = s32Index*10 + (int)(u8CharInput - '0');
                    //printf("%c", u8CharInput);
                }
            }

            if(u8CharInput==0xa) // Enter
            {
                if(s32CharNumber == 0)
                {
                    printf("\nNo item be select!!\n");
                    printf("\n------------------------------------\n");
                    printf("Please input the selection : ");
                    continue;
                }
                else
                {
                    printf("\nSelection is : %d \n", s32Index);
            break;
                }
            }

            if((u8CharInput == 0x8) || (u8CharInput == 0x7f)) // backspace, Delete
            {
                if(s32CharNumber > 0)
                {
                    printf("\rPlease input the selection : ");
                    for(s32ClearTextIndex=0;s32ClearTextIndex<=s32CharNumber;s32ClearTextIndex++)
                    {
                        printf(" ");
                    }
                    s32CharNumber--;
                    s32Index = s32Index / 10;
                    printf("\rPlease input the selection : ");
                    if(s32Index!=0)
                    {
                        printf("%d",s32Index);
                    }
                }
            }

            if(u8CharInput==0x71) // q (quit)
            {
                printf("\nExit test suite \n");
                break;
            }
        }

        if(u8CharInput==0x71) // q (quit)
        {
            printf("\nExit test suite \n");
            break;
        }

        if((s32Index >= s32MenuNum) || (s32Index < 0))
        {
            printf("Error, no matching \n");
            continue;
        }

        printf("%s\n", MENU_TABLE[s32Index].NAME);
        printf("\n\n");
        MENU_TABLE[s32Index].func_ptr();
        printf("\n\nPress any key to continue.");
        //getchar();
    }
}

int main(void)
{
    __test_suite__();
    return 0;
}

