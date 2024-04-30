////////////////////////////////////////////////////////////////////////
// SHA related api
////////////////////////////////////////////////////////////////////////
static void test_sha1(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha1(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(20, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha1.html\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_sha224(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha224(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(28, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha224.html\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_sha256(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha256(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(32, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha256.html\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_sha384(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha384(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(48, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha384.html\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_sha512(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha512(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(64, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha512.html\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_sha512_224(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha512_224(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(28, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha512_224.html\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_sha512_256(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha512_256(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(32, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha512_256.html\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_sha3_sha224(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha3_sha224(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(28, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha3_sha224.html\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_sha3_sha256(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha3_sha256(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(32, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha3_sha256.html\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_sha3_sha384(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha3_sha384(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(48, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha3_sha384.html\n");
    _TEST_SUITE_TRACE_OUT
}

static void test_sha3_sha512(void)
{
    _TEST_SUITE_TRACE_IN

    // test data
    char au8Data[10] ={0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    char au8Hash[64]={0};

    // how to call sw api
    sec_hash_sha3_sha512(au8Data, au8Hash, sizeof(au8Data));

    // debug log
    printf("data(HEX), size = %d\n", sizeof(au8Data));
    _DUMP(sizeof(au8Data), au8Data);
    _DUMP(64, au8Hash);
    printf("you can check result in online tool:\n");
    printf("https://emn178.github.io/online-tools/sha3_sha512.html\n");
    _TEST_SUITE_TRACE_OUT
}

