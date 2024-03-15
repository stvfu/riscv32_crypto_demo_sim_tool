#include <stdio.h>
#include <sec_api.h>
#include <libtom_test.h>
#include <mbedtls_test.h>

void sec_GenRandomBuffer(char *out_buf, int size, CryptoLib eLibSetting)
{
    switch(eLibSetting)
    {
        case ENUM_MBEDTLS:
            printf("mbedtls Gen Random Buffer Test\n");
            printf("  Not Support\n"); 
	    printf("\n\n");
	    break;
        case ENUM_LIBTOM: 
            printf("Libtom Gen Random Buffer Test\n");
	    libtom_gen_random_buffer(out_buf, size);
            printf("\n\n");
	    break;
	default:
	    printf("Not Support\n");
            break;
    }
}
