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

int sec_hash_sha512_224(char * msg, char* sha_out, int msg_len)
{
    _SEC_TRACE_IN
    hash_state md_sha512_224;
    sha512_224_init(&md_sha512_224);
    sha512_224_process(&md_sha512_224,
                      (const unsigned char *)msg,
                      (long unsigned int)msg_len); // size_of data
    sha512_224_done(&md_sha512_224,
                   (unsigned char *)sha_out);
    _SEC_TRACE_OUT
    return 0;
}

int sec_hash_sha512_256(char * msg, char* sha_out, int msg_len)
{
    _SEC_TRACE_IN
    hash_state md_sha512_256;
    sha512_256_init(&md_sha512_256);
    sha512_256_process(&md_sha512_256,
                      (const unsigned char *)msg,
                      (long unsigned int)msg_len); // size_of data
    sha512_256_done(&md_sha512_256,
                   (unsigned char *)sha_out);
    _SEC_TRACE_OUT
    return 0;
}

int sec_hash_sha3_sha224(char * msg, char* sha_out, int msg_len)
{
    _SEC_TRACE_IN
    hash_state md_sha224;
    sha3_224_init(&md_sha224);
    sha3_process(&md_sha224,
                 (const unsigned char *)msg,
                 (long unsigned int)msg_len); // size_of data
    sha3_done(&md_sha224,
             (unsigned char *)sha_out);
    _SEC_TRACE_OUT
    return 0;
}

int sec_hash_sha3_sha256(char * msg, char* sha_out, int msg_len)
{
    _SEC_TRACE_IN
    hash_state md_sha256;
    sha3_256_init(&md_sha256);
    sha3_process(&md_sha256,
                 (const unsigned char *)msg,
                 (long unsigned int)msg_len); // size_of data
    sha3_done(&md_sha256,
             (unsigned char *)sha_out);
    _SEC_TRACE_OUT
    return 0;
}

int sec_hash_sha3_sha384(char * msg, char* sha_out, int msg_len)
{
    _SEC_TRACE_IN
    hash_state md_sha384;
    sha3_384_init(&md_sha384);
    sha3_process(&md_sha384,
                 (const unsigned char *)msg,
                 (long unsigned int)msg_len); // size_of data
    sha3_done(&md_sha384,
             (unsigned char *)sha_out);
    _SEC_TRACE_OUT
    return 0;
}

int sec_hash_sha3_sha512(char * msg, char* sha_out, int msg_len)
{
    _SEC_TRACE_IN
    hash_state md_sha512;
    sha3_512_init(&md_sha512);
    sha3_process(&md_sha512,
                 (const unsigned char *)msg,
                 (long unsigned int)msg_len); // size_of data
    sha3_done(&md_sha512,
             (unsigned char *)sha_out);
    _SEC_TRACE_OUT
    return 0;
}
