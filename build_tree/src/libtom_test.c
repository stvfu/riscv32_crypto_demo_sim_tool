#include <stdio.h>
#include <tomcrypt.h>

#define AES_SETUP aes_setup
#define AES_ENC   aes_ecb_encrypt
#define AES_DEC   aes_ecb_decrypt
#define AES_DONE  aes_done
#define AES_TEST  aes_test
#define AES_KS    aes_keysize

#define REGISTER_PRNG(h) do {\
   LTC_ARGCHK(register_prng(h) != -1); \
} while(0)

#define DO(x) do { x; } while (0);

const struct ltc_prng_descriptor yarrow_desc1 =
{
    "yarrow1", 64,
    &yarrow_start,
    &yarrow_add_entropy,
    &yarrow_ready,
    &yarrow_read,
    &yarrow_done,
    &yarrow_export,
    &yarrow_import,
    &yarrow_test
};

const struct ltc_cipher_descriptor aes_desc1 =
{
    "aes1",
    6,
    16, 32, 16, 10,
    AES_SETUP, AES_ENC, AES_DEC, AES_TEST, AES_DONE, AES_KS,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

prng_state yarrow_prng;

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

void libtom_rsa_genkey(void)
{
   char e[2048]={0};
   char d[2048]={0};
   char N[2048]={0};
   char p[2048]={0};
   char q[2048]={0};
   char qP[2048]={0};
   char dP[2048]={0};
   char dQ[2048]={0};

   rsa_key key;
   key.type=0;
   key.e=e;
   key.d=d;
   key.N=N;
   key.p=p;
   key.q=q;
   key.qP=qP;
   key.dP=dP;
   key.dQ=dQ;

   int prng_idx = 0;

   printf("res_genkey start\n");
   REGISTER_PRNG(&yarrow_desc);

   prng_idx = find_prng("yarrow");

   if (prng_idx == -1) {
      fprintf(stderr, "rsa_test requires SHA1 and yarrow");
      return;
   }

   rsa_make_key(&yarrow_prng, prng_idx, 1024/8, 3, &key);

   printf("res_genkey end\n");
   return;
}

void libtom_aes_cbc_test(void)
{
    #define TEST_BUFFER_SIZE 64
    #define IV_DATA "1234567812345678"

    unsigned char pt[TEST_BUFFER_SIZE] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    unsigned char encrypt_buf[TEST_BUFFER_SIZE] = { 0 };

    char key[16] = "1234567812345678";
    unsigned char iv[16] = IV_DATA;

    unsigned char ct[64], tmp[64], iv2[16];
    int cipher_idx;

    symmetric_CBC cbc;
    unsigned long l;

    register_cipher(&aes_desc1);

    printf("  test buf:");
    _DUMP_(64, pt);

    printf("  key buf:");
    _DUMP_(16, key);

    printf("  iv buf:");
    _DUMP_(16, iv);

    /* get idx of AES handy */
    cipher_idx = find_cipher("aes1");
    if (cipher_idx == -1) {
       printf("test requires AES\n");
       return;
    }

    /* test CBC mode */
    /* encode the block */
    cbc_start(cipher_idx, iv, key, 16, 0, &cbc);
    l = sizeof(iv2);
    cbc_getiv(iv2, &l, &cbc);
    if (l != 16 || memcmp(iv2, iv, 16)) {
       printf("cbc_getiv failed\n");
       return;
    }
    cbc_encrypt(pt, ct, 64, &cbc);
    printf("  encrypted to orig buf:");
    _DUMP_(64, ct);

    /* decode the block */
    cbc_setiv(iv2, l, &cbc);
    zeromem(tmp, sizeof(tmp));
    cbc_decrypt(ct, tmp, 64, &cbc);
    if (memcmp(tmp, pt, 64) != 0) {
       printf("CBC failed\n");
       return;
    }
    printf("  decrypted to orig buf:");
    _DUMP_(64, tmp);

    printf("online tool verify: https://www.lddgo.net/en/encrypt/aes\n");
    return;
}

void libtom_gen_random_buffer(char* out_buf, int size)
{
    unsigned long res = 0;
    unsigned char *random_buffer = malloc(size);

    res = rng_get_bytes(random_buffer, size, NULL);

    memcpy(out_buf, random_buffer, size);
    _DUMP_(size, random_buffer);
    free(random_buffer);
}

void libtom_test(void)
{
    printf("\n\033[33m  libtom aes cbc test\033[0m\n");
    libtom_aes_cbc_test();

    //unsigned char data[]={0x0,0x1,0x2,0x3,0x4};
    char string[] = "Hello, world!";
    int x;

    //int hash_idx = register_hash(&sha256_desc);
    unsigned char hash[64]={0};

    printf("\n\033[33m  libtom md5 test\033[0m\n");
    hash_state md_md5;
    md5_init(&md_md5);
    md5_process(&md_md5, string, 13); // size_of data
    md5_done(&md_md5,hash);
    _DUMP_(16, hash);


    printf("\n\033[33m  libtom sha1 test\033[0m\n");
    hash_state md_sha1;
    sha1_init(&md_sha1);
    sha1_process(&md_sha1, string, 13); // size_of data
    sha1_done(&md_sha1,hash);
    _DUMP_(20, hash);


    printf("\n\033[33m  libtom sha256 test\033[0m\n");
    hash_state md_sha256;
    sha256_init(&md_sha256);
    sha256_process(&md_sha256, string, 13); // size_of data
    sha256_done(&md_sha256,hash);
    _DUMP_(32, hash);

    printf("\n\033[33m  libtom sha512 test\033[0m\n");
    hash_state md_sha512;
    sha512_init(&md_sha512);
    sha512_process(&md_sha512, string, 13); // size_of data
    sha512_done(&md_sha512,hash);
    _DUMP_(64, hash);


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

