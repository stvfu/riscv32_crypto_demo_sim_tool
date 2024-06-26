static void test(void);
static void test_printf(void);
static void test_lib(void);
static void test_libtom(void);
static void test_mebtls(void);
static void test_random(void);
static void test_random_libtom(void);
static void test_random_mbedtls(void);

static void test_sha1(void);
static void test_sha256(void);
static void test_sha224(void);
static void test_sha384(void);
static void test_sha512(void);
static void test_sha512_224(void);
static void test_sha512_256(void);
static void test_sha3_sha256(void);
static void test_sha3_sha224(void);
static void test_sha3_sha384(void);
static void test_sha3_sha512(void);

static void test_aes_ecb_encrypt(void);
static void test_aes_ecb_decrypt(void);
static void test_aes_cbc_encrypt(void);
static void test_aes_cbc_decrypt(void);
static void test_aes_ctr_encrypt(void);
static void test_aes_ctr_decrypt(void);
static void test_aes_cmac(void);
static void test_rsa_genkey(void);
static void test_rsa_sign(void);
static void test_rsa_verify(void);

static void test_ecc_genkey(void);
static void test_ecc_p256_genkey(void);
static void test_ecc_p384_genkey(void);
static void test_ecc_p521_genkey(void);
static void test_ecc_bp256_genkey(void);
static void test_ecc_bp384_genkey(void);
static void test_ecc_bp512_genkey(void);

static void test_ecdsa_sign(void);
static void test_ecdsa_p256_sign(void);
static void test_ecdsa_p384_sign(void);
static void test_ecdsa_p521_sign(void);
static void test_ecdsa_bp256_sign(void);
static void test_ecdsa_bp384_sign(void);
static void test_ecdsa_bp512_sign(void);

static void test_ecdsa_verify(void);
static void test_ecdsa_p256_verify(void);
static void test_ecdsa_p384_verify(void);
static void test_ecdsa_p521_verify(void);
static void test_ecdsa_bp256_verify(void);
static void test_ecdsa_bp384_verify(void);
static void test_ecdsa_bp512_verify(void);
static void test_ecdsa_p256_test(void);
static void test_ecdsa_p384_test(void);
static void test_ecdsa_p521_test(void);
static void test_ecdh_test(void);

static void switch_to_hash_menu(void);
static void switch_to_aes_menu(void);
static void switch_to_rsa_menu(void);
static void switch_to_ecc_menu(void);

static MENU MENU_TABLE_HASH[] = {
    // sha
    { "test sha1",                           &test_sha1},
    { "test sha224",                         &test_sha224},
    { "test sha256",                         &test_sha256},
    { "test sha384",                         &test_sha384},
    { "test sha512",                         &test_sha512},
    { "test sha512_224",                     &test_sha512_224},
    { "test sha512_256",                     &test_sha512_256},
    { "test sha3 sha224",                    &test_sha3_sha224},
    { "test sha3 sha256",                    &test_sha3_sha256},
    { "test sha3 sha384",                    &test_sha3_sha384},
    { "test sha3 sha512",                    &test_sha3_sha512},
};

static MENU MENU_TABLE_AES[] = {
    // aes
    { "test aes ecb encrypt",                &test_aes_ecb_encrypt},
    { "test aes ecb encrypt",                &test_aes_ecb_decrypt},
    { "test aes cbc encrypt",                &test_aes_cbc_encrypt},
    { "test aes cbc decrypt",                &test_aes_cbc_decrypt},
    { "test aes ctr decrypt",                &test_aes_ctr_encrypt},
    { "test aes ctr decrypt",                &test_aes_ctr_decrypt},
    { "test aes cmac",                       &test_aes_cmac},
};

static MENU MENU_TABLE_RSA[] = {
    // rsa
    { "test rsa gen key",                    &test_rsa_genkey},
    { "test rsa verify",                     &test_rsa_verify},
    { "test rsa sign",                       &test_rsa_sign},
};

static MENU MENU_TABLE_ECC[] = {
    // ecc
    { "test ecc gen p-256 key",              &test_ecc_p256_genkey},
    { "test ecc gen p-384 key",              &test_ecc_p384_genkey},
    { "test ecc gen p-521 key",              &test_ecc_p521_genkey},
    { "test ecc gen bp-256 key",             &test_ecc_bp256_genkey},
    { "test ecc gen bp-384 key",             &test_ecc_bp384_genkey},
    { "test ecc gen bp-512 key",             &test_ecc_bp512_genkey},

    // ecdsa
    { "test ecdsa sign",                     &test_ecdsa_sign},
    { "test ecdsa p-256 sign",               &test_ecdsa_p256_sign},
    { "test ecdsa p-384 sign",               &test_ecdsa_p384_sign},
    { "test ecdsa p-521 sign",               &test_ecdsa_p521_sign},
    { "test ecdsa bp-256 sign",              &test_ecdsa_bp256_sign},
    { "test ecdsa bp-384 sign",              &test_ecdsa_bp384_sign},
    { "test ecdsa bp-512 sign",              &test_ecdsa_bp512_sign},

    { "test ecdsa verify",                   &test_ecdsa_verify},
    { "test ecdsa p-256 verify",             &test_ecdsa_p256_verify},
    { "test ecdsa p-384 verify",             &test_ecdsa_p384_verify},
    { "test ecdsa p-521 verify",             &test_ecdsa_p521_verify},
    { "test ecdsa bp-256 verify",            &test_ecdsa_bp256_verify},
    { "test ecdsa bp-384 verify",            &test_ecdsa_bp384_verify},
    { "test ecdsa bp-512 verify",            &test_ecdsa_bp512_verify},

    // ecdh
    { "test ecdsa p-256 genkey+sign+verify", &test_ecdsa_p256_test},
    { "test ecdsa p-384 genkey+sign+verify", &test_ecdsa_p384_test},
    { "test ecdsa p-521 genkey+sign+verify", &test_ecdsa_p521_test},

    // ecdh
    { "test ecdh test",                      &test_ecdh_test},

};

    // common
static MENU MENU_TABLE[] = {
    // common
    { "spike printf test",                   &test_printf},
    { "static lib link test(add api)",       &test_lib},
    //{ "test libtom (all)",                   &test_libtom},
    //{ "test libmbedtls (all)",               &test_mebtls},

    // random
    { "test random",                         &test_random},
    { "HASH test case",                      &switch_to_hash_menu},
    { "AES  test case",                      &switch_to_aes_menu},
    { "RSA  test case",                      &switch_to_rsa_menu},
    { "ECC  test case",                      &switch_to_ecc_menu},
    //{ "  test random(mbedtls)(not support)", &test_random_libtom},
    //{ "  test random(libtom)",               &test_random_mbedtls},
    // other
    { "(todo)test case template",            &test},
};
