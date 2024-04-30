#include <stdio.h>

#include <add.h>
#include <libtom_test.h>
#include <mbedtls_test.h>
#include <sec_api.h>

typedef struct MENU{
    char *NAME;
    void (*func_ptr)(void);
}MENU;

#define _TEST_SUITE_TRACE_IN  printf("[%s][%d] Test case start\n", __func__,__LINE__);
#define _TEST_SUITE_TRACE_OUT printf("[%s][%d] Test case end\n", __func__,__LINE__);

#include "test_case.inc"

static void _DUMP(int length, char *Adr)
{
    int i;
    for(i=0;i<length;i++)
    {
        if(i % 16 == 0)
        {
                printf("\n0x%.4X: ",i + (int)Adr);
        }

        if(i % 8 == 0)
            printf(" ");

        printf("%.2X ",(int)Adr[i]);
    }
    printf("\n\n");
}

////////////////////////////////////////////////////////////////////////
// common api
////////////////////////////////////////////////////////////////////////
static void test(void)
{
    printf("Test case template\n");
}

static void test_printf(void)
{
    printf("Hello world!!\n");
}

static void test_lib(void)
{
    printf("static lib test\n");
    printf("  add test: 2+3 = %d\n",add_test(2,3));
}

static void test_libtom(void)
{
    libtom_test();
}

static void test_mebtls(void)
{
    mbedtls_test();
}

////////////////////////////////////////////////////////////////////////
// random related api
////////////////////////////////////////////////////////////////////////
static void test_random(void)
{
    char random_buffer[32] = {0};
    sec_generate_random_buffer(random_buffer, 32);
}

////////////////////////////////////////////////////////////////////////
// SHA related api
////////////////////////////////////////////////////////////////////////
#include "test_case_hash.inc"

////////////////////////////////////////////////////////////////////////
// AES related API
////////////////////////////////////////////////////////////////////////
#include "test_case_aes.inc"

////////////////////////////////////////////////////////////////////////
// RSA related API
////////////////////////////////////////////////////////////////////////
#include "test_case_rsa.inc"

////////////////////////////////////////////////////////////////////////
// ECC related API
////////////////////////////////////////////////////////////////////////
#include "test_case_ecc.inc"

////////////////////////////////////////////////////////////////////////
// Test case Menu related API
////////////////////////////////////////////////////////////////////////
void __test_suite_message__(void)
{
    printf("\n\n");
    printf("-----------------------------------------------\n");
    printf(" RISC-V crypto test suit\n");
    printf("-----------------------------------------------\n");
    int s32Index;
    int s32MenuNum = sizeof(MENU_TABLE)/sizeof(MENU);
    for(s32Index=0;s32Index<s32MenuNum;s32Index++)
    {
    printf("%2d.  %s\n", s32Index, MENU_TABLE[s32Index].NAME);
    }
    printf(" q.  exit\n");
    printf("-----------------------------------------------\n");
    printf("Please input the selection : \n");

}

void __test_suite__(void)
{
    printf("\n\nEnter RISC-V Crypto Test Sueite\n");

    char u8CharInput;
    int s32Index = 0;
    int s32CharNumber = 0;
    int s32ClearTextIndex = 0;
    int s32MenuNum = sizeof(MENU_TABLE)/sizeof(MENU);

    while(1)
    {
        s32Index = 0;
        s32CharNumber = 0;
        __test_suite_message__();

        // char input
        while(1)
        {
            u8CharInput = (char)getchar();
            //printf("u8CharInput = 0x%x\n", u8CharInput);

            if((u8CharInput >= 0x30)&&(u8CharInput <= 0x39)) // 0~9
            {
                if(s32CharNumber < 2)
                {
                    s32CharNumber++;
                    s32Index = s32Index*10 + (int)(u8CharInput - '0');
                    //printf("%c", u8CharInput);
                }
            }

            if(u8CharInput==0xa) // Enter
            {
                if(s32CharNumber == 0)
                {
                    printf("\nNo item be select!!\n");
                    printf("\n------------------------------------\n");
                    printf("Please input the selection : ");
                    continue;
                }
                else
                {
                    printf("\nSelection is : %d \n", s32Index);
            break;
                }
            }

            if((u8CharInput == 0x8) || (u8CharInput == 0x7f)) // backspace, Delete
            {
                if(s32CharNumber > 0)
                {
                    printf("\rPlease input the selection : ");
                    for(s32ClearTextIndex=0;s32ClearTextIndex<=s32CharNumber;s32ClearTextIndex++)
                    {
                        printf(" ");
                    }
                    s32CharNumber--;
                    s32Index = s32Index / 10;
                    printf("\rPlease input the selection : ");
                    if(s32Index!=0)
                    {
                        printf("%d",s32Index);
                    }
                }
            }

            if(u8CharInput==0x71) // q (quit)
            {
                printf("\nExit test suite \n");
                break;
            }
        }

        if(u8CharInput==0x71) // q (quit)
        {
            printf("\nExit test suite \n");
            break;
        }

        if((s32Index >= s32MenuNum) || (s32Index < 0))
        {
            printf("Error, no matching \n");
            continue;
        }

        printf("%s\n", MENU_TABLE[s32Index].NAME);
        printf("\n\n");
        MENU_TABLE[s32Index].func_ptr();
        printf("\n\nPress any key to continue.");
        //getchar();
    }
}

int main(void)
{
    __test_suite__();
    return 0;
}

