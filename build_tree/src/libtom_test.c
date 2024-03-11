#include <stdio.h>
#include <tomcrypt.h>

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
    printf("\n");
	//DUMP_1((int)length, (char *)Adr);
}


void libtom_test(void)
{
    printf("\n\033[33m  libtom sha256 test\033[0m\n");
    //unsigned char data[]={0x0,0x1,0x2,0x3,0x4};
    char string[] = "Hello, world!";
    int x;

    int hash_idx = register_hash(&sha256_desc);
    unsigned char hash[]={0};
    hash_state md;
    sha256_init(&md);
    sha256_process(&md, string, 13); // size_of data
    sha256_done(&md,hash);
    _DUMP_(32, hash);

    printf("\n\n\033[33m  libtom gen random test 1\033[0m\n");
    unsigned long res = 0;
    unsigned char random_buffer[32] = {0};
    res = rng_get_bytes(random_buffer, 32, NULL);
     _DUMP_(32, random_buffer);

    printf("\n\n\033[33m  libtom gen random test 1\033[0m\n");
    res = rng_get_bytes(random_buffer, 32, NULL);
    _DUMP_(32, random_buffer);
    return;
}
