typedef enum {
    ENUM_MBEDTLS,
    ENUM_LIBTOM
} CryptoLib;

typedef enum {
    E_ECC_P192,
    E_ECC_P224,
    E_ECC_P256,
    E_ECC_P384,
    E_ECC_P521,
    E_ECC_BRAINPOLLP256R1,
    E_ECC_BRAINPOLLP384R1,
    E_ECC_BRAINPOLLP512R1,
    E_ECC_LAST,
} E_Sec_Ecc_Curves;

typedef enum {
    E_HASH_SHA1,
    E_HASH_SHA224,
    E_HASH_SHA256,
    E_HASH_SHA384,
    E_HASH_SHA512,
    E_HASH_SHA512_224,
    E_HASH_SHA512_256,
    E_HASH_SHA3_224,
    E_HASH_SHA3_SHA256,
    E_HASH_SHA3_SHA384,
    E_HASH_SHA3_SHA512,
    E_HASH_LAST,
} E_Sec_Hash_algo;

// random
int sec_generate_random_buffer(char *out_buf, int size);

// sha
int sec_hash(char * msg, char* sha_out, int msg_len, E_Sec_Hash_algo eHashAlgo);
int sec_hash_sha1(char * msg, char* sha_out, int msg_len);
int sec_hash_sha224(char * msg, char* sha_out, int msg_len);
int sec_hash_sha256(char * msg, char* sha_out, int msg_len);
int sec_hash_sha384(char * msg, char* sha_out, int msg_len);
int sec_hash_sha512(char * msg, char* sha_out, int msg_len);
int sec_hash_sha512_224(char * msg, char* sha_out, int msg_len);
int sec_hash_sha512_256(char * msg, char* sha_out, int msg_len);
int sec_hash_sha3_sha224(char * msg, char* sha_out, int msg_len);
int sec_hash_sha3_sha256(char * msg, char* sha_out, int msg_len);
int sec_hash_sha3_sha384(char * msg, char* sha_out, int msg_len);
int sec_hash_sha3_sha512(char * msg, char* sha_out, int msg_len);

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

int sec_rsa_sign(char* exp,
                 char* p,
                 char* q,
                 char* dP,
                 char* dQ,
                 char* qInv,
                 int size_n_in_words,
                 int size_e_in_words,
                 int size_p_in_words,
                 int hash_type,
                 char *add_message,
                 int message_size_in_words,
                 char *add_signature,
                 int signature_size_in_words);

// ECC
int sec_ecdsa_p256_test(void);
int sec_ecdsa_p384_test(void);
int sec_ecdsa_p521_test(void);
int sec_ecc_generate_key(char* private_d, char* public_Q_X, char* public_Q_Y, int u32EccCurves);
int sec_ecdsa_sign(char* private_d, int size_d_in_bytes,
                   char* public_Q_X, int size_Q_X_in_bytes,
                   char* public_Q_Y, int size_Q_Y_in_bytes,
                   char* add_message, int size_m_in_bytes,
                   char* r_in_MSW, int size_r_in_bytes,
                   char* s_in_MSW, int size_s_in_bytes,
                   int hash_type,
                   int u32EccCurves);

int sec_ecdsa_verify(char* public_Q_X, int size_Q_X_in_bytes,
                            char* public_Q_Y, int size_Q_Y_in_bytes,
                            char* add_message, int size_m_in_bytes,
                            char* r_in_MSW, int size_r_in_bytes,
                            char* s_in_MSW, int size_s_in_bytes,
                            int hash_type,
                            int u32EccCurves);

int sec_ecdh_test(void);

