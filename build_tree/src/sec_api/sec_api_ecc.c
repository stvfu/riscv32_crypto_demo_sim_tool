#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <sec_api.h>
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"

#define assert_exit(cond, ret) \
    do { if (!(cond)) { \
        printf("  !. assert: failed [line: %d, error: -0x%04X]\n", __LINE__, -ret); \
        goto cleanup; \
    } } while (0)

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

static void sec_print_ecdsa_key(char * string, const mbedtls_mpi *X)
{
    char tempbuf[1024];
    int templen = 0;

    mbedtls_mpi_write_string(X, 16, (char *)tempbuf, sizeof(tempbuf), (size_t *)&templen);
    mbedtls_printf("%s: %s\n", string, tempbuf);
}

static void sec_show_all_ecdsa_key(mbedtls_ecdsa_context ctx)
{
    printf("\nShow ECDSA Key\n");
    sec_print_ecdsa_key("ecdsa private   d", &ctx.d);
    sec_print_ecdsa_key("ecdsa public  Q_X", &ctx.Q.X);
    sec_print_ecdsa_key("ecdsa public  Q_Y", &ctx.Q.Y);
    printf("ECC setting\n");
    sec_print_ecdsa_key("ecdsa ecc param   P", &ctx.grp.P);
    sec_print_ecdsa_key("ecdsa ecc param   A", &ctx.grp.A);
    sec_print_ecdsa_key("ecdsa ecc param   B", &ctx.grp.B);
    sec_print_ecdsa_key("ecdsa ecc param G_X", &ctx.grp.G.X);
    sec_print_ecdsa_key("ecdsa ecc param G_Y", &ctx.grp.G.Y);
    sec_print_ecdsa_key("ecdsa ecc param   N", &ctx.grp.N);
    sec_print_ecdsa_key("ecdsa ecc param T_X", &ctx.grp.T->X);
    sec_print_ecdsa_key("ecdsa ecc param T_Y", &ctx.grp.T->Y);
}

int sec_ecc_generate_key(char* private_d, char* public_Q_X, char* public_Q_Y)
{
    int ret = 0;
    char buf[97];
    uint8_t hash[32], msg[100];
    const char *pers = "simple_ecdsa";

    char tempbuf[256];
    int templen = 0;
    size_t dlen, qlen;
    size_t q_xlen;
    size_t q_ylen;
    memset(msg, 0x12, sizeof(msg));

    mbedtls_ecdsa_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    // Initialize the ECDSA structure
    mbedtls_ecdsa_init(&ctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
                                sw_entropy, &entropy,
                                (const uint8_t *)pers,
                                strlen(pers));

    assert_exit(ret == 0, ret);
    mbedtls_printf("\n  . setup rng ... ok\n\n");

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
    q_xlen = mbedtls_mpi_size(&ctx.Q.X);
    q_ylen = mbedtls_mpi_size(&ctx.Q.Y);

    // copy key to buffer
    mbedtls_mpi_write_binary(&ctx.d , (unsigned char *)private_d, (size_t)dlen);
    mbedtls_mpi_write_binary(&ctx.Q.X , (unsigned char *)public_Q_X, (size_t)q_xlen);
    mbedtls_mpi_write_binary(&ctx.Q.Y , (unsigned char *)public_Q_Y, (size_t)q_ylen);

    sec_show_all_ecdsa_key(ctx);

cleanup:
    mbedtls_ecdsa_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return(ret != 0);
}

int sec_ecdsa_sign(char* private_d, char* public_Q_X, char* public_Q_Y, char* add_message, int size_m_in_bytes, char* r_in_MSW, char* s_in_MSW, int hash_type)
{
    int ret = 0;
    char buf[97];
    uint8_t hash[32];
    const char *pers = "simple_ecdsa";

    char tempbuf[256];
    int templen = 0;

    size_t rlen, slen;
    size_t dlen = 0;
    size_t qlen = 0;
    size_t q_xlen;
    size_t q_ylen;

    mbedtls_mpi r, s;

    char au8Key[65]= {0};
    au8Key[0]=0x04;
    memcpy((void *)(au8Key+1), (const void *)public_Q_X, (size_t)32);
    memcpy((void *)(au8Key+33), (const void *)public_Q_Y, (size_t)32);

    // init struct
    mbedtls_ecdsa_context ctx;
    mbedtls_md_context_t md_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    // Initialize the ECDSA structure
    mbedtls_ecdsa_init(&ctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // setup random
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
                                sw_entropy, &entropy,
                                (const uint8_t *)pers,
                                strlen(pers));
    assert_exit(ret == 0, ret);
    mbedtls_printf("\n  . setup rng ... ok\n\n");

    //generate ECDSA key pair
    mbedtls_ecp_keypair public_key;
    mbedtls_ecp_keypair_init(&public_key);

    mbedtls_ecp_point_init(&public_key.Q);

    mbedtls_ecp_group_init(&public_key.grp);
    mbedtls_ecp_group_load(&public_key.grp, MBEDTLS_ECP_DP_SECP256R1);
    //ret = mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP256R1);

    // set private key
//    mbedtls_mpi_read_binary(&ctx.Q.X, (const unsigned char *)public_Q_X, 32);
//    mbedtls_mpi_read_binary(&ctx.Q.Y, (const unsigned char *)public_Q_Y, 32);
    mbedtls_mpi_read_binary(&public_key.d, (const unsigned char *)private_d, (size_t)32);
    mbedtls_ecp_point_read_binary(&public_key.grp,
                                  &public_key.Q,
                                  (const unsigned char *)au8Key,
                                  (size_t)sizeof(au8Key));

    mbedtls_ecdsa_from_keypair(&ctx, &public_key);


    sec_show_all_ecdsa_key(ctx);
    // hash
    mbedtls_md_init(&md_ctx);
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
               (const unsigned char *)add_message,
               sizeof(add_message), hash);
    mbedtls_printf("  1. hash ... ok\n"); //calculate the hash value of msg

    // set public key (point)

    mbedtls_printf("  2. ecdsa generate keypair:\n");
    //_DUMP_((int)(qlen + dlen), (char *)buf);
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
    // copy key to buffer
    mbedtls_mpi_write_binary(&r , (unsigned char *)r_in_MSW, (size_t)rlen);
    mbedtls_mpi_write_binary(&s , (unsigned char *)s_in_MSW, (size_t)slen);

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_md_free(&md_ctx);
    mbedtls_ecdsa_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return 0;
}

int sec_ecdsa_verify(char* public_Q_X,
                     char* public_Q_Y,
                     char* add_message,
                     int size_m_in_bytes,
                     char* r_in_MSW,
                     char* s_in_MSW,
                     int hash_type)
{
    return 0;
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
