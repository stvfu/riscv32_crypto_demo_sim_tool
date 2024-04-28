#include <stdio.h>
#include <stdint.h>
#include <sec_api.h>
#include <customization_wrapper.h>

#define CUSTOMIZATION_TRACE_IN_OUT_LOG_ENABLE

#define _CUSTOMIZATION_TRACE_IN  printf("[%s][%d] IN\n", __func__,__LINE__);
#define _CUSTOMIZATION_TRACE_OUT printf("[%s][%d] OUT\n", __func__,__LINE__);

// Software implementation
// random
customization_error_t customization_trng_generate_random_buffer(uint32_t * datas, uint32_t unmber_of_words)
{
    _CUSTOMIZATION_TRACE_IN
    sec_generate_random_buffer((char*) datas, (int)unmber_of_words);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

// SHA
customization_error_t customization_hash_sha1(uint32_t * msg, uint32_t* sha_out, uint32_t msg_len)
{
    _CUSTOMIZATION_TRACE_IN
    sec_hash_sha1((char *)msg, (char*)sha_out, (int)msg_len);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_hash_sha224(uint32_t * msg, uint32_t* sha_out, uint32_t msg_len)
{
    _CUSTOMIZATION_TRACE_IN
    sec_hash_sha224((char *)msg, (char*)sha_out, (int)msg_len);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_hash_sha256(uint32_t * msg, uint32_t* sha_out, uint32_t msg_len)
{
    _CUSTOMIZATION_TRACE_IN
    sec_hash_sha256((char *)msg, (char*)sha_out, (int)msg_len);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_hash_sha384(uint32_t * msg, uint32_t* sha_out, uint32_t msg_len)
{
    _CUSTOMIZATION_TRACE_IN
    sec_hash_sha384((char *)msg, (char*)sha_out, (int)msg_len);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_hash_sha512(uint32_t * msg, uint32_t* sha_out, uint32_t msg_len)
{
    _CUSTOMIZATION_TRACE_IN
    sec_hash_sha512((char *)msg, (char*)sha_out, (int)msg_len);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

// AES
customization_error_t customization_bc_aes_ecb_enc(uint8_t key_size_in_bytes,
                               uint32_t *add_key,
                               uint32_t *add_src,
                               uint32_t *add_dest,
                               uint32_t tr_size_in_bytes)
{
    _CUSTOMIZATION_TRACE_IN
    sec_aes_ecb_enc((int)key_size_in_bytes,
                    (char *)add_key,
                    (char *)add_src,
                    (char *)add_dest,
                    (int)tr_size_in_bytes);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_bc_aes_ecb_dec(uint8_t key_size_in_bytes,
                               uint32_t *add_key,
                               uint32_t *add_src,
                               uint32_t *add_dest,
                               uint32_t tr_size_in_bytes)
{
    _CUSTOMIZATION_TRACE_IN
    sec_aes_ecb_dec((int)key_size_in_bytes,
                    (char *)add_key,
                    (char *)add_src,
                    (char *)add_dest,
                    (int)tr_size_in_bytes);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_bc_aes_cbc_enc(uint8_t key_size_in_bytes,
                               uint32_t *add_key,
                               uint32_t *add_iv,
                               uint32_t *add_src,
                               uint32_t *add_dest,
                               uint32_t tr_size_in_bytes)
{
    _CUSTOMIZATION_TRACE_IN
    sec_aes_cbc_enc((int)key_size_in_bytes,
                    (char *)add_key,
                    (char *)add_iv,
                    (char *)add_src,
                    (char *)add_dest,
                    (int)tr_size_in_bytes);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_bc_aes_cbc_dec(uint8_t key_size_in_bytes,
                               uint32_t *add_key,
                               uint32_t *add_iv,
                               uint32_t *add_src,
                               uint32_t *add_dest,
                               uint32_t tr_size_in_bytes)
{
    _CUSTOMIZATION_TRACE_IN
    sec_aes_cbc_dec((int)key_size_in_bytes,
                    (char *)add_key,
                    (char *)add_iv,
                    (char *)add_src,
                    (char *)add_dest,
                    (int)tr_size_in_bytes);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_bc_aes_ctr_enc(uint8_t key_size_in_bytes,
                               uint32_t *add_key,
                               uint32_t *add_iv,
                               uint32_t *add_src,
                               uint32_t *add_dest,
                               uint32_t tr_size_in_bytes)
{
    _CUSTOMIZATION_TRACE_IN
    sec_aes_ctr_enc((int)key_size_in_bytes,
                    (char *)add_key,
                    (char *)add_iv,
                    (char *)add_src,
                    (char *)add_dest,
                    (int)tr_size_in_bytes);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_bc_aes_ctr_dec(uint8_t key_size_in_bytes,
                               uint32_t *add_key,
                               uint32_t *add_iv,
                               uint32_t *add_src,
                               uint32_t *add_dest,
                               uint32_t tr_size_in_bytes)
{
    _CUSTOMIZATION_TRACE_IN
    sec_aes_ctr_dec((int)key_size_in_bytes,
                    (char *)add_key,
                    (char *)add_iv,
                    (char *)add_src,
                    (char *)add_dest,
                    (int)tr_size_in_bytes);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_bc_aes_cmac(uint8_t key_size_in_bytes,
                            uint32_t *add_key,
                            uint32_t *add_src,
                            uint32_t *add_dest,
                            uint32_t tr_size_in_bytes)
{
    _CUSTOMIZATION_TRACE_IN
    sec_aes_cmac((int)key_size_in_bytes,
                 (char *)add_key,
                 (char *)add_src,
                 (char *)add_dest,
                 (int)tr_size_in_bytes);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

// RSA
customization_error_t customization_rsa_generate_key(uint32_t* const n,
                                 uint32_t* const p,
                                 uint32_t* const q,
                                 uint32_t* const dP,
                                 uint32_t* const dQ,
                                 uint32_t* const qInv,
                                 uint32_t size_n_in_words)
{
    _CUSTOMIZATION_TRACE_IN
    sec_rsa_generate_key((char*)n,
                         (char*)p,
                         (char*)q,
                         (char*)dP,
                         (char*)dQ,
                         (char*)qInv,
                         (int)65537,
                         (int)size_n_in_words);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_rsa_verify(uint32_t* n,
                           uint32_t* exp,
                           uint16_t  size_n_in_words,
                           uint16_t  size_e_in_words,
                           uint32_t  hash_type,
                           const uint32_t  *add_message,
                           uint32_t message_size_in_words,
                           const uint32_t  *add_signature,
                           uint32_t signature_size_in_words)
{
    _CUSTOMIZATION_TRACE_IN
    sec_rsa_verify((char*)n,
                   (char*)exp,
                   (int)(size_n_in_words),
                   (int)(size_e_in_words),
                   (int)hash_type,
                   (char *)add_message,
                   (int)message_size_in_words,
                   (char *)add_signature,
                   (int)signature_size_in_words);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

// ECC
customization_error_t customization_ecc_p256_generate_key(char* private_d, char* public_Q_X, char* public_Q_Y)
{
    _CUSTOMIZATION_TRACE_IN
    sec_ecc_generate_key((char*)private_d, (char*)public_Q_X, (char*)public_Q_Y, (int)E_ECC_P256);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_ecc_p384_generate_key(char* private_d, char* public_Q_X, char* public_Q_Y)
{
    _CUSTOMIZATION_TRACE_IN
    sec_ecc_generate_key((char*)private_d, (char*)public_Q_X, (char*)public_Q_Y, (int)E_ECC_P384);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_ecc_p521_generate_key(char* private_d, char* public_Q_X, char* public_Q_Y)
{
    _CUSTOMIZATION_TRACE_IN
    sec_ecc_generate_key((char*)private_d, (char*)public_Q_X, (char*)public_Q_Y, (int)E_ECC_P521);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}
customization_error_t customization_ecc_bp256_generate_key(char* private_d, char* public_Q_X, char* public_Q_Y)
{
    _CUSTOMIZATION_TRACE_IN
    sec_ecc_generate_key((char*)private_d, (char*)public_Q_X, (char*)public_Q_Y, (int)E_ECC_BRAINPOLLP256R1);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_ecc_bp384_generate_key(char* private_d, char* public_Q_X, char* public_Q_Y)
{
    _CUSTOMIZATION_TRACE_IN
    sec_ecc_generate_key((char*)private_d, (char*)public_Q_X, (char*)public_Q_Y, (int)E_ECC_BRAINPOLLP384R1);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_ecc_bp512_generate_key(char* private_d, char* public_Q_X, char* public_Q_Y)
{
    _CUSTOMIZATION_TRACE_IN
    sec_ecc_generate_key((char*)private_d, (char*)public_Q_X, (char*)public_Q_Y, (int)E_ECC_BRAINPOLLP512R1);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_ecdsa_sign(char* private_d, int size_d_in_bytes,
                           char* public_Q_X, int size_Q_X_in_bytes,
                           char* public_Q_Y, int size_Q_Y_in_bytes,
                           char* add_message, int size_m_in_bytes,
                           char* r_in_MSW, int size_r_in_bytes,
                           char* s_in_MSW, int size_s_in_bytes,
                           int hash_type)
{
    _CUSTOMIZATION_TRACE_IN
    sec_ecdsa_sign((char*)private_d, (int)size_d_in_bytes,
                   (char*)public_Q_X, (int)size_Q_X_in_bytes,
                   (char*)public_Q_Y, (int)size_Q_Y_in_bytes,
                   (char*)add_message, (int)size_m_in_bytes,
                   (char*)r_in_MSW, (int)size_r_in_bytes,
                   (char*)s_in_MSW, (int)size_s_in_bytes,
                   (int)hash_type,
                   (int)E_ECC_P256);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_ecdsa_verify(char* public_Q_X, int size_Q_X_in_bytes,
                                char* public_Q_Y, int size_Q_Y_in_bytes,
                                char* add_message, int size_m_in_bytes,
                                char* r_in_MSW, int size_r_in_bytes,
                                char* s_in_MSW, int size_s_in_bytes,
                                int hash_type)
{
    _CUSTOMIZATION_TRACE_IN
    sec_ecdsa_verify((char*)public_Q_X, (int)size_Q_X_in_bytes,
                     (char*)public_Q_Y, (int)size_Q_X_in_bytes,
                     (char*)add_message, (int)size_m_in_bytes,
                     (char*)r_in_MSW, (int)size_r_in_bytes,
                     (char*)s_in_MSW, (int)size_s_in_bytes,
                     (int)hash_type,
                     (int)E_ECC_P256);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_ecdsa_p256_sign(char* private_d, int size_d_in_bytes,
                           char* public_Q_X, int size_Q_X_in_bytes,
                           char* public_Q_Y, int size_Q_Y_in_bytes,
                           char* add_message, int size_m_in_bytes,
                           char* r_in_MSW, int size_r_in_bytes,
                           char* s_in_MSW, int size_s_in_bytes,
                           int hash_type)
{
    _CUSTOMIZATION_TRACE_IN
    sec_ecdsa_sign((char*)private_d, (int)size_d_in_bytes,
                   (char*)public_Q_X, (int)size_Q_X_in_bytes,
                   (char*)public_Q_Y, (int)size_Q_Y_in_bytes,
                   (char*)add_message, (int)size_m_in_bytes,
                   (char*)r_in_MSW, (int)size_r_in_bytes,
                   (char*)s_in_MSW, (int)size_s_in_bytes,
                   (int)hash_type,
                   (int)E_ECC_P256);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_ecdsa_p256_verify(char* public_Q_X, int size_Q_X_in_bytes,
                                char* public_Q_Y, int size_Q_Y_in_bytes,
                                char* add_message, int size_m_in_bytes,
                                char* r_in_MSW, int size_r_in_bytes,
                                char* s_in_MSW, int size_s_in_bytes,
                                int hash_type)
{
    _CUSTOMIZATION_TRACE_IN
    sec_ecdsa_verify((char*)public_Q_X, (int)size_Q_X_in_bytes,
                     (char*)public_Q_Y, (int)size_Q_X_in_bytes,
                     (char*)add_message, (int)size_m_in_bytes,
                     (char*)r_in_MSW, (int)size_r_in_bytes,
                     (char*)s_in_MSW, (int)size_s_in_bytes,
                     (int)hash_type,
                     (int)E_ECC_P256);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_ecdsa_p384_sign(char* private_d, int size_d_in_bytes,
                           char* public_Q_X, int size_Q_X_in_bytes,
                           char* public_Q_Y, int size_Q_Y_in_bytes,
                           char* add_message, int size_m_in_bytes,
                           char* r_in_MSW, int size_r_in_bytes,
                           char* s_in_MSW, int size_s_in_bytes,
                           int hash_type)
{
    _CUSTOMIZATION_TRACE_IN
    sec_ecdsa_sign((char*)private_d, (int)size_d_in_bytes,
                   (char*)public_Q_X, (int)size_Q_X_in_bytes,
                   (char*)public_Q_Y, (int)size_Q_Y_in_bytes,
                   (char*)add_message, (int)size_m_in_bytes,
                   (char*)r_in_MSW, (int)size_r_in_bytes,
                   (char*)s_in_MSW, (int)size_s_in_bytes,
                   (int)hash_type,
                   (int)E_ECC_P384);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_ecdsa_p384_verify(char* public_Q_X, int size_Q_X_in_bytes,
                                char* public_Q_Y, int size_Q_Y_in_bytes,
                                char* add_message, int size_m_in_bytes,
                                char* r_in_MSW, int size_r_in_bytes,
                                char* s_in_MSW, int size_s_in_bytes,
                                int hash_type)
{
    _CUSTOMIZATION_TRACE_IN
    sec_ecdsa_verify((char*)public_Q_X, (int)size_Q_X_in_bytes,
                     (char*)public_Q_Y, (int)size_Q_X_in_bytes,
                     (char*)add_message, (int)size_m_in_bytes,
                     (char*)r_in_MSW, (int)size_r_in_bytes,
                     (char*)s_in_MSW, (int)size_s_in_bytes,
                     (int)hash_type,
                     (int)E_ECC_P384);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_ecdsa_p521_sign(char* private_d, int size_d_in_bytes,
                           char* public_Q_X, int size_Q_X_in_bytes,
                           char* public_Q_Y, int size_Q_Y_in_bytes,
                           char* add_message, int size_m_in_bytes,
                           char* r_in_MSW, int size_r_in_bytes,
                           char* s_in_MSW, int size_s_in_bytes,
                           int hash_type)
{
    _CUSTOMIZATION_TRACE_IN
    sec_ecdsa_sign((char*)private_d, (int)size_d_in_bytes,
                   (char*)public_Q_X, (int)size_Q_X_in_bytes,
                   (char*)public_Q_Y, (int)size_Q_Y_in_bytes,
                   (char*)add_message, (int)size_m_in_bytes,
                   (char*)r_in_MSW, (int)size_r_in_bytes,
                   (char*)s_in_MSW, (int)size_s_in_bytes,
                   (int)hash_type,
                   (int)E_ECC_P521);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_ecdsa_p521_verify(char* public_Q_X, int size_Q_X_in_bytes,
                                char* public_Q_Y, int size_Q_Y_in_bytes,
                                char* add_message, int size_m_in_bytes,
                                char* r_in_MSW, int size_r_in_bytes,
                                char* s_in_MSW, int size_s_in_bytes,
                                int hash_type)
{
    _CUSTOMIZATION_TRACE_IN
    sec_ecdsa_verify((char*)public_Q_X, (int)size_Q_X_in_bytes,
                     (char*)public_Q_Y, (int)size_Q_X_in_bytes,
                     (char*)add_message, (int)size_m_in_bytes,
                     (char*)r_in_MSW, (int)size_r_in_bytes,
                     (char*)s_in_MSW, (int)size_s_in_bytes,
                     (int)hash_type,
                     (int)E_ECC_P521);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_ecdsa_bp256_sign(char* private_d, int size_d_in_bytes,
                           char* public_Q_X, int size_Q_X_in_bytes,
                           char* public_Q_Y, int size_Q_Y_in_bytes,
                           char* add_message, int size_m_in_bytes,
                           char* r_in_MSW, int size_r_in_bytes,
                           char* s_in_MSW, int size_s_in_bytes,
                           int hash_type)
{
    _CUSTOMIZATION_TRACE_IN
    sec_ecdsa_sign((char*)private_d, (int)size_d_in_bytes,
                   (char*)public_Q_X, (int)size_Q_X_in_bytes,
                   (char*)public_Q_Y, (int)size_Q_Y_in_bytes,
                   (char*)add_message, (int)size_m_in_bytes,
                   (char*)r_in_MSW, (int)size_r_in_bytes,
                   (char*)s_in_MSW, (int)size_s_in_bytes,
                   (int)hash_type,
                   (int)E_ECC_BRAINPOLLP256R1);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_ecdsa_bp256_verify(char* public_Q_X, int size_Q_X_in_bytes,
                                char* public_Q_Y, int size_Q_Y_in_bytes,
                                char* add_message, int size_m_in_bytes,
                                char* r_in_MSW, int size_r_in_bytes,
                                char* s_in_MSW, int size_s_in_bytes,
                                int hash_type)
{
    _CUSTOMIZATION_TRACE_IN
    sec_ecdsa_verify((char*)public_Q_X, (int)size_Q_X_in_bytes,
                     (char*)public_Q_Y, (int)size_Q_X_in_bytes,
                     (char*)add_message, (int)size_m_in_bytes,
                     (char*)r_in_MSW, (int)size_r_in_bytes,
                     (char*)s_in_MSW, (int)size_s_in_bytes,
                     (int)hash_type,
                     (int)E_ECC_BRAINPOLLP256R1);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_ecdsa_bp384_sign(char* private_d, int size_d_in_bytes,
                           char* public_Q_X, int size_Q_X_in_bytes,
                           char* public_Q_Y, int size_Q_Y_in_bytes,
                           char* add_message, int size_m_in_bytes,
                           char* r_in_MSW, int size_r_in_bytes,
                           char* s_in_MSW, int size_s_in_bytes,
                           int hash_type)
{
    _CUSTOMIZATION_TRACE_IN
    sec_ecdsa_sign((char*)private_d, (int)size_d_in_bytes,
                   (char*)public_Q_X, (int)size_Q_X_in_bytes,
                   (char*)public_Q_Y, (int)size_Q_Y_in_bytes,
                   (char*)add_message, (int)size_m_in_bytes,
                   (char*)r_in_MSW, (int)size_r_in_bytes,
                   (char*)s_in_MSW, (int)size_s_in_bytes,
                   (int)hash_type,
                   (int)E_ECC_BRAINPOLLP384R1);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_ecdsa_bp384_verify(char* public_Q_X, int size_Q_X_in_bytes,
                                char* public_Q_Y, int size_Q_Y_in_bytes,
                                char* add_message, int size_m_in_bytes,
                                char* r_in_MSW, int size_r_in_bytes,
                                char* s_in_MSW, int size_s_in_bytes,
                                int hash_type)
{
    _CUSTOMIZATION_TRACE_IN
    sec_ecdsa_verify((char*)public_Q_X, (int)size_Q_X_in_bytes,
                     (char*)public_Q_Y, (int)size_Q_X_in_bytes,
                     (char*)add_message, (int)size_m_in_bytes,
                     (char*)r_in_MSW, (int)size_r_in_bytes,
                     (char*)s_in_MSW, (int)size_s_in_bytes,
                     (int)hash_type,
                     (int)E_ECC_BRAINPOLLP384R1);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}
customization_error_t customization_ecdsa_bp512_sign(char* private_d, int size_d_in_bytes,
                           char* public_Q_X, int size_Q_X_in_bytes,
                           char* public_Q_Y, int size_Q_Y_in_bytes,
                           char* add_message, int size_m_in_bytes,
                           char* r_in_MSW, int size_r_in_bytes,
                           char* s_in_MSW, int size_s_in_bytes,
                           int hash_type)
{
    _CUSTOMIZATION_TRACE_IN
    sec_ecdsa_sign((char*)private_d, (int)size_d_in_bytes,
                   (char*)public_Q_X, (int)size_Q_X_in_bytes,
                   (char*)public_Q_Y, (int)size_Q_Y_in_bytes,
                   (char*)add_message, (int)size_m_in_bytes,
                   (char*)r_in_MSW, (int)size_r_in_bytes,
                   (char*)s_in_MSW, (int)size_s_in_bytes,
                   (int)hash_type,
                   (int)E_ECC_BRAINPOLLP512R1);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}

customization_error_t customization_ecdsa_bp512_verify(char* public_Q_X, int size_Q_X_in_bytes,
                                char* public_Q_Y, int size_Q_Y_in_bytes,
                                char* add_message, int size_m_in_bytes,
                                char* r_in_MSW, int size_r_in_bytes,
                                char* s_in_MSW, int size_s_in_bytes,
                                int hash_type)
{
    _CUSTOMIZATION_TRACE_IN
    sec_ecdsa_verify((char*)public_Q_X, (int)size_Q_X_in_bytes,
                     (char*)public_Q_Y, (int)size_Q_X_in_bytes,
                     (char*)add_message, (int)size_m_in_bytes,
                     (char*)r_in_MSW, (int)size_r_in_bytes,
                     (char*)s_in_MSW, (int)size_s_in_bytes,
                     (int)hash_type,
                     (int)E_ECC_BRAINPOLLP512R1);
    _CUSTOMIZATION_TRACE_OUT
    return 0;
}


