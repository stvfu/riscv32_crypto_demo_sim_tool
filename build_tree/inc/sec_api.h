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
int sec_aes_ecb_enc(int key_size_in_bytes, char *add_key, char *add_src, char *add_dest, int tr_size_in_bytes);
int sec_aes_ecb_dec(int key_size_in_bytes, char *add_key, char *add_src, char *add_dest, int tr_size_in_bytes);

int sec_aes_cbc_enc(int key_size_in_bytes, char *add_key, char *add_iv, char *add_src, char *add_dest, int tr_size_in_bytes);
int sec_aes_cbc_dec(int key_size_in_bytes, char *add_key, char *add_iv, char *add_src, char *add_dest, int tr_size_in_bytes);

int sec_aes_ctr_enc(int key_size_in_bytes, char *add_key, char *add_iv, char *add_src, char *add_dest, int tr_size_in_bytes);
int sec_aes_ctr_dec(int key_size_in_bytes, char *add_key, char *add_iv, char *add_src, char *add_dest, int tr_size_in_bytes);

int sec_aes_cmac(int key_size_in_bytes, char *add_key, char *add_src, char *add_dest, int tr_size_in_bytes);

// RSA
void sec_GenRandomBuffer(char *out_buf, int size);
void sec_GenRsaKey(void);
int sec_rsa_generate_key(char* n, char* p, char* q, char* dP, char* dQ, char* qInv, int e_value, int size_n_bits);
int sec_rsa_verify(char* n, char* exp, int size_n_in_words, int size_e_in_words, int hash_type, char *add_message, int message_size_in_words, char *add_signature, int signature_size_in_words);

// ECC
int sec_ecdsa_test(void);
int sec_ecdh_test(void);
