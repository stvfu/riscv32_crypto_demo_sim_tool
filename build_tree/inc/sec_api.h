typedef enum {
    ENUM_MBEDTLS,
    ENUM_LIBTOM
} CryptoLib;

// random
int sec_generate_random_buffer(char *out_buf, int size);

// sha
int sec_hash_sha1(char * msg, char* sha_out, int msg_len);
int sec_hash_sha224(char * msg, char* sha_out, int msg_len);
int sec_hash_sha256(char * msg, char* sha_out, int msg_len);
int sec_hash_sha384(char * msg, char* sha_out, int msg_len);
int sec_hash_sha512(char * msg, char* sha_out, int msg_len);

// AES

// RSA
void sec_GenRandomBuffer(char *out_buf, int size);
void sec_GenRsaKey(void);
int sec_rsa_generate_key(char* n, char* p, char* q, char* dP, char* dQ, char* qInv, int e_value, int size_n_bits);
// ECC
