#include <stdio.h>

#include <add.h>
#include <libtom_test.h>
#include <mbedtls_test.h>

int main(void) {
    printf("Hello! World!\n");
    // add test

    printf("\n\033[33m========================================================\033[0m\n");
    printf("\033[33mTest1: static lib test:\033[0m\n");
    printf("  add test: 2+3 = %d\n",add_test(2,3));

    printf("\n\033[33m========================================================\033[0m\n");
    printf("\033[33mTest2: libtom test:\033[0m\n");
    libtom_test();

    printf("\n\033[33m========================================================\033[0m\n");
    printf("\n\033[33mTest3: mbedtls test:\033[0m\n");
    mbedtls_test();

    printf("\033[33m========================================================\033[0m\n");
    return 0;
}
