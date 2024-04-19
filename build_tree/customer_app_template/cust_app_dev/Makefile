Q=@
# strict compilation option enable flags
# enable : for release
# disable: for dev
STRICT_COMPLIER_OPTION=enable

# toolchain setting
TOOLCHAIN_PREFIX=riscv32-corev-elf
CC=$(TOOLCHAIN_PREFIX)-gcc
LD=$(TOOLCHAIN_PREFIX)-ld
AR=$(TOOLCHAIN_PREFIX)-ar

# service name
SERVICE = custapp

# base test app setting
BIN        = demo

# release
RELEASE_PACKAGE = ./release_package

OUTPUT_PATH=./out
INCDIR += -I./inc
INCDIR += -I./inc/libtom
INCDIR += -I./inc/mbedtls
INCDIR += -I./inc/sec_api

# MODULE_INDIR setting in ./module/module.mk
include ./module/module.mk
INCDIR += $(MODULE_INCDIR)

# mbedtsl macro
CFLAGS+= -DMBEDTLS_ALLOW_PRIVATE_ACCESS

# strict compiler options
ifeq ($(STRICT_COMPLIER_OPTION),enable)
CFLAGS+= -fdata-sections
CFLAGS+= -fdiagnostics-color=always
CFLAGS+= -ffunction-sections
CFLAGS+= -fno-builtin
CFLAGS+= -fno-common
CFLAGS+= -fno-jump-tables
CFLAGS+= -fno-merge-all-constants
CFLAGS+= -fstack-usage
CFLAGS+= -g0
CFLAGS+= -march=rv32ic_zicsr
CFLAGS+= -Os
CFLAGS+= -std=gnu11
CFLAGS+= -Wa,-march=rv32ic_zicsr
CFLAGS+= -Wall
CFLAGS+= -Walloca
CFLAGS+= -Walloc-zero
CFLAGS+= -Wconversion
CFLAGS+= -Wdouble-promotion
CFLAGS+= -Wduplicated-branches
CFLAGS+= -Werror
CFLAGS+= -Wextra
CFLAGS+= -Wformat=2
CFLAGS+= -Wformat-overflow=2
CFLAGS+= -Wformat-truncation=2
CFLAGS+= -Wjump-misses-init
CFLAGS+= -Wlogical-op
CFLAGS+= -Wmissing-format-attribute
CFLAGS+= -Wno-deprecated-declarations
CFLAGS+= -Wno-unused-function
CFLAGS+= -Wno-unused-parameter
CFLAGS+= -Wno-unused-variable
CFLAGS+= -Wnull-dereference
CFLAGS+= -Wpointer-arith
CFLAGS+= -Wshadow
CFLAGS+= -Wstrict-prototypes
CFLAGS+= -Wvla
endif

CFLAGS += $(INCDIR)
LDFLAGS +=

LDLIBS += -L./lib/libtom/$(TOOLCHAIN_PREFIX)
LDLIBS += -L./lib/mbedtls/$(TOOLCHAIN_PREFIX)
LDLIBS += -L./lib/sec_api

#source
SRCS += $(wildcard src/*.c)
# MODULE_INDIR setting in ./module/module.mk
SRCS += $(MODULE_SRCS)

# Library linker setting
# test app -> call service entry
# MOULDE_TEST_LIBS setting in ./module/module.mk
LIBS += $(MOULDE_TEST_LIBS)

# service entry -> call module implement function
LIBS += -l$(SERVICE)_entry

# module implement function -> call sw function
# MOULDE_LIBS setting in ./module/module.mk
LIBS += $(MOULDE_LIBS)

# sw function -> call opensource function
LIBS += -lMyLib

#  opensource function
LIBS += -ltomcrypt
LIBS += -lmbedcrypto -lmbedtls -lmbedx509

# parse module list
MODULE_LIST := $(patsubst module/module_%,%,$(wildcard module/module_*))

# object
OBJS := $(SRCS:.c=.o)
SUS := $(SRCS:.c=.su)

all: $(BIN) gen_lib release

release: gen_lib
	$(Q)rm -rf $(RELEASE_PACKAGE)
	$(Q)mkdir -p $(RELEASE_PACKAGE)
	$(Q)cp -r $(OUTPUT_PATH)/lib$(SERVICE)_entry.a $(RELEASE_PACKAGE)/
	$(Q)cp -r $(OUTPUT_PATH)/lib$(SERVICE)_module_*.a $(RELEASE_PACKAGE)/
	$(Q)rm -rf $(RELEASE_PACKAGE)/*test.a

	$(Q)cp -r ./inc/$(SERVICE).h $(RELEASE_PACKAGE)/
	$(Q)cp -r ./module/*/*.h $(RELEASE_PACKAGE)/

$(BIN): gen_lib $(MODULE_LIST)
	@echo "  Build $(BIN) :"
	$(Q)$(CC) $(CFLAGS) -o $(OUTPUT_PATH)/$@ test/main.c $(LDFLAGS) $(LDLIBS) -L$(OUTPUT_PATH) $(LIBS)

$(MODULE_LIST): gen_lib
	@echo "   gen module_$@ library"
	$(Q)$(AR) -rcs $(OUTPUT_PATH)/lib$(SERVICE)_module_$@.a      ./module/module_$@/$(SERVICE)_module_$@_entry.o
	$(Q)$(AR) -rcs $(OUTPUT_PATH)/lib$(SERVICE)_module_$@_test.a ./module/module_$@/$(SERVICE)_module_$@_test.o
      
gen_lib: $(OBJS)
	@echo "   object (.o) --> library(.a)"
	$(Q)mkdir $(OUTPUT_PATH)
	$(Q)$(AR) -rcs $(OUTPUT_PATH)/lib$(SERVICE)_entry.a ./src/$(SERVICE)_entry.o
	@echo "   library complier option:"
	@echo "   CFLAGS = $(CFLAGS)"

%.o: %.c
	@echo "   CC   $<"
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo '  CLEAN $(OUTPUT_PATH)'
	$(Q)rm -rf $(OBJS)
	$(Q)rm -rf $(SUS)
	$(Q)rm -rf $(OUTPUT_PATH)
	$(Q)rm -rf $(RELEASE_PACKAGE)
