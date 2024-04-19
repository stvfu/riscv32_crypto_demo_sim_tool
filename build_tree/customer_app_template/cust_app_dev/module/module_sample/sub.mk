MODULE_INCDIR += -I./module/module_sample
MODULE_SRCS += $(wildcard module/module_sample/*.c)
MOULDE_TEST_LIBS += -lcustapp_module_sample_test
MOULDE_LIBS += -lcustapp_module_sample

