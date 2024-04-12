#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <sec_api.h>
#include <tomcrypt.h>

#include <libtom_test.h>
#include <mbedtls_test.h>

#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"

#define MBEDTLS_AES_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_GENPRIME
#define MBEDTLS_MD_C
#define MBEDTLS_OID_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_AES_ROM_TABLES

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
int sw_entropy(void *data, unsigned char *output, size_t size) {
    ((void) data);
    sec_generate_random_buffer((char *)output, (int)size);
    return 0;
}

int sec_generate_random_buffer(char *out_buf, int size)
{
    _SEC_TRACE_IN
    libtom_gen_random_buffer(out_buf, size);
    _SEC_TRACE_OUT
    return 0;
}

// SHA
int sec_hash_sha1(char * msg, char* sha_out, int msg_len)
{
    _SEC_TRACE_IN
    hash_state md_sha1;
    sha1_init(&md_sha1);
    sha1_process(&md_sha1, msg, msg_len); // size_of data
    sha1_done(&md_sha1,sha_out);
    _SEC_TRACE_OUT
    return 0;
}

int sec_hash_sha224(char * msg, char* sha_out, int msg_len)
{
    _SEC_TRACE_IN
    hash_state md_sha224;
    sha224_init(&md_sha224);
    sha224_process(&md_sha224, msg, msg_len); // size_of data
    sha224_done(&md_sha224,sha_out);
    _SEC_TRACE_OUT
    return 0;
}

int sec_hash_sha256(char * msg, char* sha_out, int msg_len)
{
    _SEC_TRACE_IN
    hash_state md_sha256;
    sha256_init(&md_sha256);
    sha256_process(&md_sha256, msg, msg_len); // size_of data
    sha256_done(&md_sha256,sha_out);
    _SEC_TRACE_OUT
    return 0;
}

int sec_hash_sha384(char * msg, char* sha_out, int msg_len)
{
    _SEC_TRACE_IN
    hash_state md_sha384;
    sha384_init(&md_sha384);
    sha384_process(&md_sha384, msg, msg_len); // size_of data
    sha384_done(&md_sha384,sha_out);
    _SEC_TRACE_OUT
    return 0;
}

int sec_hash_sha512(char * msg, char* sha_out, int msg_len)
{
    _SEC_TRACE_IN
    hash_state md_sha512;
    sha512_init(&md_sha512);
    sha512_process(&md_sha512, msg, msg_len); // size_of data
    sha512_done(&md_sha512,sha_out);
    _SEC_TRACE_OUT
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
                                        size_n_bits, // n key size module lens (2048)
                                        e_value); // e key 0x10001
    assert_exit(ret == 0, ret);
    mbedtls_printf("\n  1. RSA generate key ... ok\n");

    uint8_t buf[516];
    mbedtls_printf("\n  +++++++++++++++++ rsa keypair +++++++++++++++++\n\n");
    mbedtls_mpi_write_string(&ctx.N , 16, buf, sizeof(buf), &olen);
    mbedtls_mpi_write_binary(&ctx.N , (unsigned char * )n, size_n_bits/8);
    mbedtls_printf("N: %s\n", buf);

    mbedtls_mpi_write_string(&ctx.E , 16, buf, sizeof(buf), &olen);
    mbedtls_printf("E: %s\n", buf);

    mbedtls_mpi_write_string(&ctx.D , 16, buf, sizeof(buf), &olen);
    mbedtls_printf("D: %s\n", buf);

    mbedtls_mpi_write_string(&ctx.P , 16, buf, sizeof(buf), &olen);
    mbedtls_printf("P: %s\n", buf);
    mbedtls_mpi_write_binary(&ctx.P , (unsigned char * )p, size_n_bits/8/2);

    mbedtls_mpi_write_string(&ctx.Q , 16, buf, sizeof(buf), &olen);
    mbedtls_printf("Q: %s\n", buf);
    mbedtls_mpi_write_binary(&ctx.Q , (unsigned char * )q, size_n_bits/8/2);

    mbedtls_mpi_write_string(&ctx.DP, 16, buf, sizeof(buf), &olen);
    mbedtls_printf("DP: %s\n", buf);
    mbedtls_mpi_write_binary(&ctx.DP , (unsigned char * )dP, size_n_bits/8/2);

    mbedtls_mpi_write_string(&ctx.DQ, 16, buf, sizeof(buf), &olen);
    mbedtls_printf("DQ: %s\n", buf);
    mbedtls_mpi_write_binary(&ctx.DQ , (unsigned char * )dQ, size_n_bits/8/2);

    mbedtls_mpi_write_string(&ctx.QP, 16, buf, sizeof(buf), &olen);
    mbedtls_printf("QP(qInv): %s\n", buf);
    mbedtls_mpi_write_binary(&ctx.QP , (unsigned char * )qInv, size_n_bits/8/2);

    mbedtls_printf("\n  +++++++++++++++++ rsa keypair +++++++++++++++++\n\n");

cleanup:
    mbedtls_ctr_drbg_free(&ctr_drbg); // release random struct
    mbedtls_entropy_free(&entropy); // release entropy struct
    mbedtls_rsa_free(&ctx);         // release rsa struct

    return;
}

