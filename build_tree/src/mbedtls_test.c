#include <stdio.h>
#include "mbedtls/md5.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

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


int mbedtls_test(void) {
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

    return 0;
}

