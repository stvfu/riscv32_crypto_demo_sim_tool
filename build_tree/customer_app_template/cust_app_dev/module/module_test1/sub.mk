MODULE_INCDIR += -I./module/module_test1
MODULE_SRCS += $(wildcard module/module_test1/*.c)
MOULDE_TEST_LIBS += -lcustapp_module_test1_test
MOULDE_LIBS += -lcustapp_module_test1

