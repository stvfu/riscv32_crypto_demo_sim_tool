#include <stdio.h>

#include <add.h>
#include <sha.h>
#include <mbedtls_test.h>

int main(void) {
    printf("Hello! World!\n");
    // add test

    printf("\n\033[33mTest1: static lib test:\033[0m\n");
    printf("add test: 2+3 = %d\n",add_test(2,3));

    printf("\n\033[33mTest2: libtom test:\033[0m\n");
    sha1__test();

    printf("\n\033[33mTest3: mbedtls test:\033[0m\n");
    mbedtls_test();
    return 0;
}
