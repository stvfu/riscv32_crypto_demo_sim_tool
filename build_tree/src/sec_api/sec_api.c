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

int sw_entropy(void *data, unsigned char *output, size_t size) {
    ((void) data);
    sec_generate_random_buffer((char *)output, (int)size);
    return 0;
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
