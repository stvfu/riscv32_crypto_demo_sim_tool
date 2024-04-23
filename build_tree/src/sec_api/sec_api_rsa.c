#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <sec_api.h>
#include <tomcrypt.h>

#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"

#define assert_exit(cond, ret) \
    do { if (!(cond)) { \
        printf("  !. assert: failed [line: %d, error: -0x%04X]\n", __LINE__, -ret); \
        goto cleanup; \
    } } while (0)

#define _SEC_TRACE_IN  printf("[%s][%d] IN\n", __func__,__LINE__);
#define _SEC_TRACE_OUT printf("[%s][%d] OUT\n", __func__,__LINE__);

void sec_GenRsaKey_impl(char* n, char* p, char* q, char* dP, char* dQ, char* qInv, int e_value, int size_n_bits);

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

// random
static int sw_entropy(void *data, unsigned char *output, size_t size) {
    ((void) data);
    sec_generate_random_buffer((char *)output, (int)size);
    return 0;
}

// RSA
int sec_rsa_generate_key(char* n, char* p, char* q, char* dP, char* dQ, char* qInv, int e_value, int size_n_bits)
{
    sec_GenRsaKey_impl(n, p, q, dP, dQ, qInv, e_value, size_n_bits);

    printf("\n N Key (%d)\n", size_n_bits);
    _DUMP_(256, (char *)n);
    printf("\n E Key = %d\n", e_value);
    printf("\n P Key\n");
    _DUMP_(128, (char *)p);
    printf("\n Q Key\n");
    _DUMP_(128, (char *)q);
    printf("\n dP\n");
    _DUMP_(128, (char *)dP);
    printf("\n dQ:\n");
    _DUMP_(128, (char *)dQ);
    printf("\n qInv:\n");
    _DUMP_(128, (char *)qInv);
    _SEC_TRACE_OUT
    return 0;
}

static void sec_print_rsa_key(char * string, const mbedtls_mpi *X)
{
    char tempbuf[1024];
    int templen = 0;

    mbedtls_mpi_write_string(X, 16, (char *)tempbuf, sizeof(tempbuf), (size_t *)&templen);
    mbedtls_printf("%s: %s\n", string, tempbuf);
}

void sec_GenRsaKey_impl(char* n, char* p, char* q, char* dP, char* dQ, char* qInv, int e_value, int size_n_bits)
{
    int ret;
    size_t olen = 0;
    uint8_t out[2048/8];

    mbedtls_rsa_context ctx; // RSA context
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    const char *pers = "simple_rsa";

    mbedtls_entropy_init(&entropy); // init entropy
    mbedtls_ctr_drbg_init(&ctr_drbg); // init random context
    mbedtls_rsa_init(&ctx); // init RSA context

    // string seed : "simple_rsa"
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, sw_entropy, &entropy,
                                (const uint8_t *) pers, strlen(pers));

    assert_exit(ret == 0, ret);
    mbedtls_printf("\n  . setup rng ... ok\n");
    mbedtls_printf("\n  ! RSA Generating large primes may take minutes!(5~10 mins) \n");

    // gen RSA key
    ret = mbedtls_rsa_gen_key(&ctx, mbedtls_ctr_drbg_random, // random
                                        &ctr_drbg, // random struct
                                        (unsigned int)size_n_bits, // n key size module lens (2048)
                                        e_value); // e key 0x10001
    assert_exit(ret == 0, ret);
    mbedtls_printf("\n  1. RSA generate key ... ok\n");

    uint8_t buf[516];
    mbedtls_printf("\n  +++++++++++++++++ rsa keypair +++++++++++++++++\n\n");
  
    sec_print_rsa_key("N       ", &ctx.N);
    sec_print_rsa_key("E       ", &ctx.E);
    sec_print_rsa_key("D       ", &ctx.D);
    sec_print_rsa_key("P       ", &ctx.P);
    sec_print_rsa_key("Q       ", &ctx.Q);
    sec_print_rsa_key("DP      ", &ctx.DP);
    sec_print_rsa_key("DQ      ", &ctx.DQ);
    sec_print_rsa_key("QP(qInv)", &ctx.QP);
  
    mbedtls_mpi_write_binary(&ctx.N, (unsigned char * )n, (size_t)(size_n_bits/8));
    mbedtls_mpi_write_binary(&ctx.P, (unsigned char * )p, (size_t)(size_n_bits/8/2));
    mbedtls_mpi_write_binary(&ctx.Q, (unsigned char * )q, (size_t)(size_n_bits/8/2));
    mbedtls_mpi_write_binary(&ctx.DP, (unsigned char * )dP, (size_t)(size_n_bits/8/2));
    mbedtls_mpi_write_binary(&ctx.DQ, (unsigned char * )dQ, (size_t)(size_n_bits/8/2));
    mbedtls_mpi_write_binary(&ctx.QP, (unsigned char * )qInv, (size_t)(size_n_bits/8/2));

    mbedtls_printf("\n  +++++++++++++++++ rsa keypair +++++++++++++++++\n\n");

cleanup:
    mbedtls_ctr_drbg_free(&ctr_drbg); // release random struct
    mbedtls_entropy_free(&entropy); // release entropy struct
    mbedtls_rsa_free(&ctx);         // release rsa struct

    return;
}

int sec_rsa_verify(char* n,
                   char* exp,
                   int size_n_in_words,
                   int size_e_in_words,
                   int hash_type,
                   char *add_message,
                   int message_size_in_words,
                   char *add_signature,
                   int signature_size_in_words)
{
    _SEC_TRACE_IN
    int u32Res = 0;
    size_t olen = 0;
    uint8_t buf[516]={0};

    mbedtls_rsa_context ctx; // RSA context
    mbedtls_rsa_init(&ctx); // init RSA context
    mbedtls_rsa_set_padding(&ctx, 0, MBEDTLS_MD_NONE);

    mbedtls_rsa_import_raw(&ctx,
                           (unsigned char const *)n,
                           (size_t)size_n_in_words,
                           NULL, //P
                           0,
                           NULL, //Q
                           0,
                           NULL, //D
                           0,
                           (unsigned char const *)exp,
                           (size_t)size_e_in_words
                           );

    mbedtls_printf("\n  +++++++++++++++++ rsa keypair +++++++++++++++++\n\n");
    mbedtls_mpi_write_string(&ctx.N , 16, (char *)buf, sizeof(buf), &olen);
    mbedtls_printf("N: %s\n", buf);

    mbedtls_mpi_write_string(&ctx.E , 16, (char *)buf, sizeof(buf), &olen);
    mbedtls_printf("E: %s\n", buf);

    u32Res = mbedtls_rsa_pkcs1_verify(&ctx,
                           (mbedtls_md_type_t)hash_type,
                           (unsigned int)message_size_in_words,
                           (const unsigned char *)add_message,
                           (const unsigned char *)add_signature);
    if(u32Res ==0)
    {
        printf("\033[32m Sig Verify Pass!\033[0m\n");

    }
    else
    {
        printf("\033[31m Sig Verify Fail!\033[0m\n");
    }

    mbedtls_rsa_free(&ctx);         // release rsa struct
    _SEC_TRACE_OUT
    return u32Res;
}
