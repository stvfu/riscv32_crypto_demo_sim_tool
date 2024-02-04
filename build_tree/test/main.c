#include <stdio.h>

#include <add.h>
#include <sha.h>

int main(void) {
    printf("Hello! World!\n");
    // add test
    printf("add test: 2+3 = %d\n",add_test(2,3));

    printf("sha1 test:\n");
    sha1__test();
    return 0;
}
