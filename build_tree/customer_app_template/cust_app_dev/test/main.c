#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <customization_wrapper.h>

void test_custapp_module_sample(void);
void test_custapp_module_test1(void);
void test_custapp_module_test2(void);
void test_custapp_module_test3(void);

int main(void)
{
    printf("Start HPSE Module test:\n");

    printf("\033[33m[0. Module sample test:]\033[0m\n");
    test_custapp_module_sample();

    printf("\033[33m[1. Module test1 test:]\033[0m\n");
    test_custapp_module_test1();

    printf("\033[33m[2. Module vesa test:]\033[0m\n");
    test_custapp_module_test2();

    printf("\033[33m[3. Module vesa test:]\033[0m\n");
    test_custapp_module_test3();

    return 0;
}
