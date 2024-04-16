#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <sec_api.h>
#include <tomcrypt.h>

#include <libtom_test.h>
#include <mbedtls_test.h>

#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/rsa.h"
#include "mbedtls/cmac.h"
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
    sha1_process(&md_sha1,
                 (const unsigned char *)msg,
                 (long unsigned int)msg_len); // size_of data
    sha1_done(&md_sha1,
             (unsigned char *)sha_out);
    _SEC_TRACE_OUT
    return 0;
}

int sec_hash_sha224(char * msg, char* sha_out, int msg_len)
{
    _SEC_TRACE_IN
    hash_state md_sha224;
    sha224_init(&md_sha224);
    sha224_process(&md_sha224,
                   (const unsigned char *)msg,
                   (long unsigned int)msg_len); // size_of data
    sha224_done(&md_sha224,
                (unsigned char *)sha_out);
    _SEC_TRACE_OUT
    return 0;
}

int sec_hash_sha256(char * msg, char* sha_out, int msg_len)
{
    _SEC_TRACE_IN
    hash_state md_sha256;
    sha256_init(&md_sha256);
    sha256_process(&md_sha256,
                   (const unsigned char *)msg,
                   (long unsigned int)msg_len); // size_of data
    sha256_done(&md_sha256,
                (unsigned char *)sha_out);
    _SEC_TRACE_OUT
    return 0;
}

int sec_hash_sha384(char * msg, char* sha_out, int msg_len)
{
    _SEC_TRACE_IN
    hash_state md_sha384;
    sha384_init(&md_sha384);
    sha384_process(&md_sha384,
                   (const unsigned char *)msg,
                   (long unsigned int)msg_len); // size_of data
    sha384_done(&md_sha384,
                (unsigned char *)sha_out);
    _SEC_TRACE_OUT
    return 0;
}

int sec_hash_sha512(char * msg, char* sha_out, int msg_len)
{
    _SEC_TRACE_IN
    hash_state md_sha512;
    sha512_init(&md_sha512);
    sha512_process(&md_sha512,
                   (const unsigned char *)msg,
                   (long unsigned int)msg_len); // size_of data
    sha512_done(&md_sha512,
                (unsigned char *)sha_out);
    _SEC_TRACE_OUT
    return 0;
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
                                        (unsigned int)size_n_bits, // n key size module lens (2048)
                                        e_value); // e key 0x10001
    assert_exit(ret == 0, ret);
    mbedtls_printf("\n  1. RSA generate key ... ok\n");

    uint8_t buf[516];
    mbedtls_printf("\n  +++++++++++++++++ rsa keypair +++++++++++++++++\n\n");
    mbedtls_mpi_write_string(&ctx.N , 16, (char *)buf, sizeof(buf), &olen);
    mbedtls_mpi_write_binary(&ctx.N , (unsigned char * )n, (size_t)(size_n_bits/8));
    mbedtls_printf("N: %s\n", buf);

    mbedtls_mpi_write_string(&ctx.E , 16, (char *)buf, sizeof(buf), &olen);
    mbedtls_printf("E: %s\n", buf);

    mbedtls_mpi_write_string(&ctx.D , 16, (char *)buf, sizeof(buf), &olen);
    mbedtls_printf("D: %s\n", buf);

    mbedtls_mpi_write_string(&ctx.P , 16, (char *)buf, sizeof(buf), &olen);
    mbedtls_printf("P: %s\n", buf);
    mbedtls_mpi_write_binary(&ctx.P , (unsigned char * )p, (size_t)(size_n_bits/8/2));

    mbedtls_mpi_write_string(&ctx.Q , 16, (char *)buf, sizeof(buf), &olen);
    mbedtls_printf("Q: %s\n", buf);
    mbedtls_mpi_write_binary(&ctx.Q , (unsigned char * )q, (size_t)(size_n_bits/8/2));

    mbedtls_mpi_write_string(&ctx.DP, 16, (char *)buf, sizeof(buf), &olen);
    mbedtls_printf("DP: %s\n", buf);
    mbedtls_mpi_write_binary(&ctx.DP , (unsigned char * )dP, (size_t)(size_n_bits/8/2));

    mbedtls_mpi_write_string(&ctx.DQ, 16, (char *)buf, sizeof(buf), &olen);
    mbedtls_printf("DQ: %s\n", buf);
    mbedtls_mpi_write_binary(&ctx.DQ , (unsigned char * )dQ, (size_t)(size_n_bits/8/2));

    mbedtls_mpi_write_string(&ctx.QP, 16, (char *)buf, sizeof(buf), &olen);
    mbedtls_printf("QP(qInv): %s\n", buf);
    mbedtls_mpi_write_binary(&ctx.QP , (unsigned char * )qInv, (size_t)(size_n_bits/8/2));

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

int sec_rsa_sign(char* p,
                 char* q,
                 char* dp,
                 char* dq,
                 char* qinv,
                 int size_p_in_words,
                 int size_q_in_words,
                 int size_dp_in_words,
                 int size_dq_in_words,
                 int size_qinv_in_words,
                 int hash_type,
                 char *add_message,
                 int message_size_in_words,
                 char *add_signature,
                 int signature_size_in_words)
{

    _SEC_TRACE_IN
    //[TODO]
    _SEC_TRACE_OUT
    return 0;
}

static void dump_buf(char *info, uint8_t *buf, uint32_t len)
{
    mbedtls_printf("%s", info);
    for (int i = 0; i < (int)len; i++) {
        mbedtls_printf("%s%02X%s", i % 16 == 0 ? "\n     ":" ",
                        buf[i], i == (int)len - 1 ? "\n":"");
    }
}

int sec_ecdsa_test(void)
{
    int ret = 0;
    char buf[97];
    uint8_t hash[32], msg[100];
    const char *pers = "simple_ecdsa";

    size_t rlen, slen, qlen, dlen;
    memset(msg, 0x12, sizeof(msg));

    //mbedtls_platform_set_printf(printf);

    mbedtls_mpi r, s;
    mbedtls_ecdsa_context ctx;
    mbedtls_md_context_t md_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_ecdsa_init(&ctx);  // Initialize the ECDSA structure
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    /*
    mbedtls_entropy_add_source(&entropy, entropy_source, NULL,
                   MBEDTLS_ENTROPY_MAX_GATHER, MBEDTLS_ENTROPY_SOURCE_STRONG);*/
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
                                sw_entropy, &entropy,
                                (const uint8_t *)pers,
                                strlen(pers));

    assert_exit(ret == 0, ret);
    mbedtls_printf("\n  . setup rng ... ok\n\n");

    mbedtls_md_init(&md_ctx);
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), msg, sizeof(msg), hash);
    mbedtls_printf("  1. hash msg ... ok\n"); //calculate the hash value of msg

    //generate ECDSA key pair
    ret = mbedtls_ecdsa_genkey(&ctx,
                               MBEDTLS_ECP_DP_SECP256R1, //select SECP256R1
                               mbedtls_ctr_drbg_random,
                               &ctr_drbg);

    assert_exit(ret == 0, ret);
    mbedtls_ecp_point_write_binary(&ctx.grp,
                                   &ctx.Q,
                                   MBEDTLS_ECP_PF_UNCOMPRESSED,
                                   &qlen,
                                   (unsigned char *)buf,
                                   sizeof(buf));

    dlen = mbedtls_mpi_size(&ctx.d);
    mbedtls_mpi_write_binary(&ctx.d, (unsigned char *)(buf + qlen), dlen);
    mbedtls_printf("  2. ecdsa generate keypair:\n");
    _DUMP_((int)(qlen + dlen), (char *)buf);

    //ECDSA signature, get r, s
    ret = mbedtls_ecdsa_sign(&ctx.grp,
                             &r,
                             &s,
                             &ctx.d,
                             hash,
                             sizeof(hash),
                             mbedtls_ctr_drbg_random,
                             &ctr_drbg);

    assert_exit(ret == 0, ret);
    rlen = mbedtls_mpi_size(&r);
    slen = mbedtls_mpi_size(&s);
    mbedtls_mpi_write_binary(&r, (unsigned char *)buf, rlen);
    mbedtls_mpi_write_binary(&s, (unsigned char *)(buf + rlen), slen);

    mbedtls_printf("  3. ecdsa generate signature:\n");
    _DUMP_((int)(rlen + slen), (char *)buf);

    //ECDSA verify
    ret = mbedtls_ecdsa_verify(&ctx.grp, hash, sizeof(hash), &ctx.Q, &r, &s);
    assert_exit(ret == 0, ret);
    mbedtls_printf("  4. ecdsa verify signature ... ok\n\n");

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_md_free(&md_ctx);
    mbedtls_ecdsa_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return(ret != 0);
}

int sec_ecdh_test(void)
{
    int ret = 0;
    size_t olen;
    char buf[65];
    mbedtls_ecp_group grp;
    mbedtls_mpi cli_secret, srv_secret;
    mbedtls_mpi cli_pri, srv_pri;
    mbedtls_ecp_point cli_pub, srv_pub;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "simple_ecdh";

    mbedtls_mpi_init(&cli_pri); //
    mbedtls_mpi_init(&srv_pri);
    mbedtls_mpi_init(&cli_secret);
    mbedtls_mpi_init(&srv_secret);
    mbedtls_ecp_group_init(&grp);     // init ecp struct
    mbedtls_ecp_point_init(&cli_pub); //init ecp point cli
    mbedtls_ecp_point_init(&srv_pub); //init ecp point srv
    mbedtls_entropy_init(&entropy);   // init entropy struct
    mbedtls_ctr_drbg_init(&ctr_drbg); // init random struct
/*
    mbedtls_entropy_add_source(&entropy, entropy_source, NULL,
                       MBEDTLS_ENTROPY_MAX_GATHER, MBEDTLS_ENTROPY_SOURCE_STRONG);*/

    mbedtls_ctr_drbg_seed(&ctr_drbg, sw_entropy, &entropy,
                                (const uint8_t *)pers, strlen((const char *)pers));
    mbedtls_printf("\n  . setup rng ... ok\n");

    // load elliptic curve and select SECP256R1
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_printf("\n  . select ecp group SECP256R1 ... ok\n");

    // cli generates public parameters
    ret = mbedtls_ecdh_gen_public(&grp,    // elliptic curve structure
                                  &cli_pri,// output cli private parameter d
                                  &cli_pub,// output cli public parameter Q
                                  mbedtls_ctr_drbg_random, &ctr_drbg);
    assert_exit(ret == 0, ret);
    mbedtls_ecp_point_write_binary(&grp,
                                   &cli_pub, // put the public parameters of cli into buf
                                   MBEDTLS_ECP_PF_UNCOMPRESSED,
                                   &olen,
                                   (unsigned char *)buf,
                                   sizeof(buf));
    mbedtls_printf("  1. ecdh client generate public parameter:\n");
    _DUMP_((int)olen, (char *)buf);
    //srv generates public parameters
    ret = mbedtls_ecdh_gen_public(&grp,     // elliptic curve structure
                                  &srv_pri, // output srv private parameter d
                                  &srv_pub, // output srv public parameter Q
                                  mbedtls_ctr_drbg_random, &ctr_drbg);
    assert_exit(ret == 0, ret);
    mbedtls_ecp_point_write_binary(&grp, &srv_pub, // export the public parameters of srv to buf
                            MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, (unsigned char *)buf, sizeof(buf));

    mbedtls_printf("  2. ecdh server generate public parameter:\n");
    _DUMP_((int)olen, (char *)buf);

    // cli calculates shared secret
    ret = mbedtls_ecdh_compute_shared(&grp,        // elliptic curve structure
                                      &cli_secret, // shared secret calculated by cli
                                      &srv_pub,    // enter srv public parameter Q
                                      &cli_pri,    // enter the private parameter d of the cli itself
                                      mbedtls_ctr_drbg_random, &ctr_drbg);
    assert_exit(ret == 0, ret);

    // export the shared key calculated by cli into buf
    mbedtls_mpi_write_binary(&cli_secret, (unsigned char *)buf, mbedtls_mpi_size(&cli_secret));
    mbedtls_printf("  3. ecdh client generate secret:\n");
    _DUMP_((int)mbedtls_mpi_size(&cli_secret), (char *)buf);

    // srv calculates shared secret
    ret = mbedtls_ecdh_compute_shared(&grp,   // elliptic curve structure
                                      &srv_secret, // the shared secret calculated by srv
                                      &cli_pub, // enter cli public parameter Q
                                      &srv_pri, // enter the private parameter d of srv itself
                                      mbedtls_ctr_drbg_random, &ctr_drbg);
    assert_exit(ret == 0, ret);
    // Export the shared key calculated by srv into buf
    mbedtls_mpi_write_binary(&srv_secret, (unsigned char *)buf, mbedtls_mpi_size(&srv_secret));

    mbedtls_printf("  4. ecdh server generate secret:\n");
    _DUMP_((int)mbedtls_mpi_size(&srv_secret), (char *)buf);

    // compare 2 value for res
    ret = mbedtls_mpi_cmp_mpi(&cli_secret, &srv_secret);
    assert_exit(ret == 0, ret);
    mbedtls_printf("  5. ecdh checking secrets ... ok\n");

cleanup:
    mbedtls_mpi_free(&cli_pri);
    mbedtls_mpi_free(&srv_pri);
    mbedtls_mpi_free(&cli_secret);
    mbedtls_mpi_free(&srv_secret);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&cli_pub);
    mbedtls_ecp_point_free(&srv_pub);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return 0;
}
