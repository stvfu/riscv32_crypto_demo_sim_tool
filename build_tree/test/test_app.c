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

static void test(void);
static void test_printf(void);
static void test_lib(void);
static void test_libtom(void);
static void test_mebtls(void);
static void test_random(void);
static void test_random_libtom(void);
static void test_random_mbedtls(void);

static void test_sha1(void);
static void test_sha256(void);
static void test_sha224(void);
static void test_sha384(void);
static void test_sha512(void);
static void test_aes_ecb_encrypt(void);
static void test_aes_ecb_decrypt(void);
static void test_aes_cbc_encrypt(void);
static void test_aes_cbc_decrypt(void);
static void test_aes_ctr_encrypt(void);
static void test_aes_ctr_decrypt(void);
static void test_aes_cmac(void);
static void test_rsa_genkey(void);
static void test_rsa_sign(void);
static void test_rsa_verify(void);
static void test_ecc_genkey(void);
static void test_ecdsa_sign(void);
static void test_ecdsa_verify(void);

static MENU MENU_TABLE[] = {
    // common
    { "spike printf test",                   &test_printf},
    { "static lib link test(add api)",       &test_lib},
    //{ "test libtom (all)",                   &test_libtom},
    //{ "test libmbedtls (all)",               &test_mebtls},

    // random
    { "test random",                         &test_random},
    //{ "  test random(mbedtls)(not support)", &test_random_libtom},
    //{ "  test random(libtom)",               &test_random_mbedtls},

    // sha
    { "test sha1",                           &test_sha1},
    { "test sha224",                         &test_sha224},
    { "test sha256",                         &test_sha256},
    { "test sha384",                         &test_sha384},
    { "test sha512",                         &test_sha512},

    // aes
    { "test aes ecb encrypt",                &test_aes_ecb_encrypt},
    { "test aes ecb encrypt",                &test_aes_ecb_decrypt},
    { "test aes cbc encrypt",                &test_aes_cbc_encrypt},
    { "test aes cbc decrypt",                &test_aes_cbc_decrypt},
    { "test aes ctr decrypt",                &test_aes_ctr_encrypt},
    { "test aes ctr decrypt",                &test_aes_ctr_decrypt},
    { "test aes cmac",                       &test_aes_cmac},

    // rsa
    { "test rsa gen key",                    &test_rsa_genkey},
    { "test rsa verify",                     &test_rsa_verify},
    { "test rsa sign",                       &test_rsa_sign},

    // ecc
    { "test ecc gen key",                    &test_ecc_genkey},
    { "test ecdsa verify",                   &test_ecdsa_verify},
    { "test ecdsa sign",                     &test_ecdsa_sign},

    // other
    { "(todo)test case template",            &test},
};

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
   //[TODO]
   printf("[TODO]\n");
}

static void test_rsa_verify(void)
{
   //[TODO]
   printf("[TODO]\n");
}
////////////////////////////////////////////////////////////////////////
// ECC related API
////////////////////////////////////////////////////////////////////////
static void test_ecc_genkey(void)
{
   //[TODO]
   printf("[TODO]\n");
}

static void test_ecdsa_sign(void)
{
   //[TODO]
   printf("[TODO]\n");
}

static void test_ecdsa_verify(void)
{
   //[TODO]
   printf("[TODO]\n");
}

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
            u8CharInput = getchar();
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

            if((u8CharInput == 0x8)&&(u8CharInput == 0x7f)) // backspace, Delete
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

