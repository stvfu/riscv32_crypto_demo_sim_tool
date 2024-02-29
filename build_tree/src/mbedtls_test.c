#include <stdio.h> // for printf
#include <string.h> // for memset
#include <stdint.h>

// for hash related test
#include "mbedtls/md5.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

// for aes related test
#include "mbedtls/aes.h"

// for rsa related test
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/rsa.h"
#include "mbedtls/platform.h"

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


#define MBEDTLS_AES_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_MD_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_GENPRIME
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_AES_ROM_TABLES

typedef struct data_tag {
    uint8_t *x;
    uint32_t    len;
} data_t;

#define TEST_EQUAL(expr1, expr2)  \
    do {                          \
        if (!(expr1 == expr2))    \
        {                         \
             goto exit;           \
	}                         \
    } while (0)

#define TEST_ASSERT(TEST)         \
    do {                          \
        if (!(TEST))              \
        {                         \
            goto exit;            \
        }                         \
    } while (0)


int mbedtls_test_read_mpi(mbedtls_mpi *X, const char *s)
{
    int negative = 0;
    /* Always set the sign bit to -1 if the input has a minus sign, even for 0.
     * This creates an invalid representation, which mbedtls_mpi_read_string()
     * avoids but we want to be able to create that in test data. */
    if (s[0] == '-') {
        ++s;
        negative = 1;
    }
    /* mbedtls_mpi_read_string() currently retains leading zeros.
     * It always allocates at least one limb for the value 0. */
    if (s[0] == 0) {
        mbedtls_mpi_free(X);
        return 0;
    }
    int ret = mbedtls_mpi_read_string(X, 16, s);
    if (ret != 0) {
        return ret;
    }
    if (negative) {
        if (mbedtls_mpi_cmp_int(X, 0) == 0) {
            //mbedtls_test_increment_case_uses_negative_0();
        }
        X->s = -1;
    }
    return 0;
}

void test_mbedtls_rsa_pkcs1_verify(data_t *message_str,
		                   int padding_mode,
                                   int digest,
				   int mod,
                                   char *input_N,
				   char *input_E,
                                   data_t *sig_str,
				   int result)
{
    DUMP_1((int)message_str->len, (char *)message_str->x);
    printf("padding_mode = %d\n", padding_mode);
    printf("digest = %d (sha256)\n", digest);
    printf("mod = %d\n", mod);
    DUMP_1((int)256, (char *)input_N);
    DUMP_1((int)16, (char *)input_E);
    DUMP_1((int)256, (char *)sig_str->x);
    //printf("result = %d\n", result);

    mbedtls_rsa_context ctx;
    mbedtls_mpi N, E;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&E);

    mbedtls_rsa_init(&ctx);
    TEST_ASSERT(mbedtls_rsa_set_padding(&ctx, padding_mode, MBEDTLS_MD_NONE) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&N, input_N) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&E, input_E) == 0);

    TEST_ASSERT(mbedtls_rsa_import(&ctx, &N, NULL, NULL, NULL, &E) == 0);

    TEST_EQUAL(mbedtls_rsa_get_len(&ctx), (size_t) ((mod + 7) / 8));

    TEST_EQUAL(mbedtls_rsa_get_bitlen(&ctx), (size_t) mod);
    TEST_ASSERT(mbedtls_rsa_check_pubkey(&ctx) == 0);

    TEST_ASSERT(mbedtls_rsa_pkcs1_verify(&ctx, digest, message_str->len, message_str->x,
                                         sig_str->x) == result);
    if(mbedtls_rsa_pkcs1_verify(&ctx, digest, message_str->len, message_str->x, sig_str->x)==0)
    {
        printf("\033[32m Verify Pass!\033[0m\n"); 
    }
    else
    {
        printf("\033[31m Verify Fail!\033[0m\n");
    }

exit:
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&E);
    mbedtls_rsa_free(&ctx);
}

void mbedtls_test_rsa(void)
{
    char hash_data[20] = { 0x8E, 0xB2, 0x08, 0xF7, 0xE0, 0x5D, 0x98, 0x7A,
                           0x9B, 0x04, 0x4A, 0x8E, 0x98, 0xC6, 0xB0, 0x87,
                           0xF1, 0x5A, 0x0B, 0xFC };
    data_t hash;
    hash.x = (uint8_t *)hash_data;
    hash.len = 20;
    char sig_data[256] = { 0xaa, 0x2d, 0x9f, 0x88, 0x33, 0x4d, 0x61, 0xbe,
                           0xd7, 0x43, 0x17, 0xba, 0x54, 0x9b, 0x14, 0x63,
                           0x60, 0x0a, 0x92, 0x19, 0x80, 0x12, 0x40, 0xcc,
                           0xa5, 0xc1, 0x1b, 0x9c, 0xdd, 0xa2, 0x93, 0x73,
                           0x17, 0x2a, 0x28, 0x15, 0x13, 0x13, 0xfb, 0x2c,
                           0xf7, 0x3b, 0xb6, 0x8a, 0xf1, 0x67, 0xe4, 0xec,
                           0x64, 0x5b, 0x6f, 0x06, 0x50, 0x28, 0x80, 0x2a,
                           0xfb, 0xcf, 0xbc, 0x10, 0xe6, 0xc2, 0xc8, 0x24,
                           0xe3, 0xc4, 0xd5, 0x0c, 0x71, 0x81, 0x19, 0x3b,
                           0x93, 0x73, 0x48, 0x32, 0x17, 0x0f, 0x0c, 0x5d,
                           0x3d, 0xd9, 0xba, 0x58, 0x08, 0xf0, 0xe2, 0xa5,
                           0xc1, 0x6b, 0x3d, 0x0d, 0xf9, 0x0d, 0xef, 0xef,
                           0xef, 0x8e, 0x8f, 0xde, 0x59, 0x06, 0x96, 0x2d,
                           0x42, 0xa2, 0xf0, 0xd6, 0x2d, 0x7f, 0x81, 0x97,
                           0x7f, 0x36, 0x7f, 0x43, 0x6f, 0x10, 0xc8, 0xb1,
                           0x18, 0x3c, 0xcf, 0x66, 0x76, 0x95, 0x3f, 0x72,
                           0x19, 0x44, 0x59, 0x38, 0xf7, 0x25, 0xd0, 0xcb,
                           0x62, 0xef, 0xba, 0xbf, 0x09, 0x2d, 0xe5, 0x31,
                           0x64, 0x28, 0x63, 0xb3, 0x81, 0xe2, 0x69, 0x4f,
                           0x2b, 0xf5, 0x44, 0xff, 0x6a, 0x4f, 0xef, 0xa7,
                           0xb3, 0x7c, 0xdb, 0xf6, 0x29, 0x2d, 0xbe, 0xdc,
                           0xac, 0xf6, 0xe5, 0x7d, 0x6f, 0x20, 0x6c, 0xe5,
                           0xdf, 0x0f, 0xd2, 0x77, 0x1f, 0x9f, 0x64, 0x81,
                           0x8f, 0x59, 0xa0, 0xab, 0x7a, 0x5f, 0x00, 0x3b,
                           0x36, 0x8d, 0xc3, 0xeb, 0x51, 0xab, 0x94, 0x09,
                           0xa0, 0xec, 0x4e, 0x43, 0xf4, 0x52, 0x81, 0xee,
                           0x9a, 0x56, 0x06, 0x64, 0xde, 0x88, 0x96, 0x5a,
                           0xb2, 0x07, 0xe2, 0x56, 0x30, 0x3d, 0x9d, 0xcb,
                           0x82, 0x33, 0xed, 0x6a, 0xd0, 0xa5, 0xad, 0x7f,
                           0x81, 0xe2, 0xf8, 0xc7, 0xa1, 0x96, 0xdc, 0x81,
                           0xe2, 0xc8, 0xb6, 0xdd, 0xe8, 0xa7, 0x7f, 0xb6,
                           0xcf, 0xd1, 0xe5, 0x47, 0x7e, 0xce, 0x9d, 0xf8 };

    data_t sig;
    sig.x = (uint8_t *)sig_data;
    sig.len = 256;

    char *N = "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f";
    char *E= "3";
    test_mbedtls_rsa_pkcs1_verify(&hash, 0, 4, 2048, N, E, &sig, 0);
    return;
}

int mbedtls_test(void) {
    printf("\n  \033[33mmbedtls aes test\033[0m\n");
    mbedtls_test_aes_cbc();

    printf("\n  \033[33mmbedtls sha test\033[0m\n");
    mbedtls_test_sha();

    printf("\n  \033[33mmbedtls random test\033[0m\n");

    printf("\n  \033[33mmbedtls rsa test\033[0m\n");
    mbedtls_test_rsa();
    return 0;
}

