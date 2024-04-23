#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <sec_api.h>
#include <tomcrypt.h>

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

int sec_generate_random_buffer(char *out_buf, int size)
{
    _SEC_TRACE_IN
    unsigned long res = 0;
    unsigned char *random_buffer = malloc((unsigned int)size);

    res = rng_get_bytes(random_buffer, (long unsigned int)size, NULL);
    if(res != 0)
    {
        printf("res = %ld\n", res);
    }
    memcpy(out_buf, random_buffer, (unsigned int)size);
    _DUMP_(size, (char *)random_buffer);
    free(random_buffer);

    _SEC_TRACE_OUT
    return 0;
}
