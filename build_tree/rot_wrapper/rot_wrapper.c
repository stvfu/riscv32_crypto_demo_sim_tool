#include <stdio.h>
#include <stdint.h>
#include <sec_api.h>
#include <rot_wrapper.h>

#define ROT_TRACE_IN_OUT_LOG_ENABLE

#define _ROT_TRACE_IN  printf("[%s][%d] IN\n", __func__,__LINE__);
#define _ROT_TRACE_OUT printf("[%s][%d] OUT\n", __func__,__LINE__);

// Software implementation
// random
rot_error_t rot_trng_generate_random_buffer(uint32_t * datas, uint32_t unmber_of_words)
{
    _ROT_TRACE_IN
    // [TODO]
    _ROT_TRACE_OUT
    return 0;
}

// SHA
rot_error_t rot_hash_sha1(uint32_t * msg, uint32_t* sha_out, uint32_t msg_len)
{
    _ROT_TRACE_IN
    sec_hash_sha1((char *)msg, (char*)sha_out, (int)msg_len);
    _ROT_TRACE_OUT
    return 0;
}

rot_error_t rot_hash_sha224(uint32_t * msg, uint32_t* sha_out, uint32_t msg_len)
{
    _ROT_TRACE_IN
    sec_hash_sha224((char *)msg, (char*)sha_out, (int)msg_len);
    _ROT_TRACE_OUT
    return 0;
}

rot_error_t rot_hash_sha256(uint32_t * msg, uint32_t* sha_out, uint32_t msg_len)
{
    _ROT_TRACE_IN
    sec_hash_sha256((char *)msg, (char*)sha_out, (int)msg_len);
    _ROT_TRACE_OUT
    return 0;
}

rot_error_t rot_hash_sha384(uint32_t * msg, uint32_t* sha_out, uint32_t msg_len)
{
    _ROT_TRACE_IN
    sec_hash_sha384((char *)msg, (char*)sha_out, (int)msg_len);
    _ROT_TRACE_OUT
    return 0;
}

rot_error_t rot_hash_sha512(uint32_t * msg, uint32_t* sha_out, uint32_t msg_len)
{
    _ROT_TRACE_IN
    sec_hash_sha512((char *)msg, (char*)sha_out, (int)msg_len);
    _ROT_TRACE_OUT
    return 0;
}

// AES
rot_error_t rot_bc_aes_ecb_enc(uint8_t key_size_in_bytes,
                               uint32_t *add_key,
                               uint32_t *add_src,
                               uint32_t *add_dest,
                               uint32_t tr_size_in_bytes)
{
    _ROT_TRACE_IN
    // [TODO]
    _ROT_TRACE_OUT
    return 0;
}

rot_error_t rot_bc_aes_ecb_dec(uint8_t key_size_in_bytes,
                               uint32_t *add_key,
                               uint32_t *add_src,
                               uint32_t *add_dest,
                               uint32_t tr_size_in_bytes)
{
    _ROT_TRACE_IN
    // [TODO]
    _ROT_TRACE_OUT
    return 0;
}


rot_error_t rot_bc_aes_cbc_enc(uint8_t key_size_in_bytes,
                               uint32_t *add_key,
                               uint32_t *add_iv,
                               uint32_t *add_src,
                               uint32_t *add_dest,
                               uint32_t tr_size_in_bytes)
{
    _ROT_TRACE_IN
    // [TODO]
    _ROT_TRACE_OUT
    return 0;
}

rot_error_t rot_bc_aes_cbc_dec(uint8_t key_size_in_bytes,
                               uint32_t *add_key,
                               uint32_t *add_iv,
                               uint32_t *add_src,
                               uint32_t *add_dest,
                               uint32_t tr_size_in_bytes)
{
    _ROT_TRACE_IN
    // [TODO]
    _ROT_TRACE_OUT
    return 0;
}

rot_error_t rot_bc_aes_ctr_enc(uint8_t key_size_in_bytes,
                               uint32_t *add_key,
                               uint32_t *add_iv,
                               uint32_t *add_src,
                               uint32_t *add_dest,
                               uint32_t tr_size_in_bytes)
{
    _ROT_TRACE_IN
    // [TODO]
    _ROT_TRACE_OUT
    return 0;
}

rot_error_t rot_bc_aes_ctr_dec(uint8_t key_size_in_bytes,
                               uint32_t *add_key,
                               uint32_t *add_iv,
                               uint32_t *add_src,
                               uint32_t *add_dest,
                               uint32_t tr_size_in_bytes)
{
    _ROT_TRACE_IN
    // [TODO]
    _ROT_TRACE_OUT
    return 0;
}

rot_error_t rot_bc_aes_cbc(uint8_t key_size_in_bytes,
                           uint32_t *add_key,
                           uint32_t *add_src,
                           uint32_t *add_dest,
                           uint32_t tr_size_in_bytes)
{
    _ROT_TRACE_IN
    // [TODO]
    _ROT_TRACE_OUT
    return 0;
}

// RSA
rot_error_t rot_rsa_generate_key(uint32_t* const n,
                                 uint32_t* const p,
                                 uint32_t* const q,
                                 uint32_t* const dP,
                                 uint32_t* const dQ,
                                 uint32_t* const qInv,
                                 uint32_t size_n_in_words)
{
    _ROT_TRACE_IN
    // [TODO]
    _ROT_TRACE_OUT
    return 0;
}

rot_error_t rot_rsa_verify(uint32_t* n,
                           uint32_t* exp,
                           uint16_t  size_n_in_words,
                           uint16_t  size_e_in_words,
                           uint32_t  hash_type,
                           const uint32_t  *add_message,
                           uint32_t message_size_in_words,
                           const uint32_t  *add_signature,
                           uint32_t signature_size_in_words)
{
    _ROT_TRACE_IN
    // [TODO]
    _ROT_TRACE_OUT
    return 0;
}

rot_error_t rot_rsa_sign(uint32_t* n,
                         uint32_t* exp,
                         uint16_t  size_n_in_words,
                         uint16_t  size_e_in_words,
                         uint32_t  hash_type,
                         const uint32_t  *add_message,
                         uint32_t message_size_in_words,
                         const uint32_t  *add_signature,
                         uint32_t signature_size_in_words)
{
    _ROT_TRACE_IN
    // [TODO]
    _ROT_TRACE_OUT
    return 0;
}

