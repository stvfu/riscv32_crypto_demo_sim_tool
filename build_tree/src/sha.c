#include <stdio.h>
#include <tomcrypt.h>
#define DUMP(data, len) \
        do { \
                int i, l = (len); \
                for (i = 0; i < l; i++) \
                printf(" 0x%02x", *((data) + i)); \
                printf("\n"); \
        } while (0)

void sha1__test()
{
        unsigned char data[]={0x0,0x1,0x2,0x3,0x4};
        int x;

        int hash_idx = register_hash(&sha256_desc);
        unsigned char hash[]={0};
        hash_state md;
        sha256_init(&md);
        sha256_process(&md, data, sizeof(data));
        sha256_done(&md,hash);
        DUMP(hash,32);
        return;
}
