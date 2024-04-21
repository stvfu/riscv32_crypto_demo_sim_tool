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

# base test app setting
TARGET     = MyLib
TARGET_LIB = lib$(TARGET).a
BIN        = demo

# dev template: user app setting
USER_APP        = user_app
USER_APP_PATH   = ./user_app
RELEASE_PACKAGE = ./release_package

OUTPUT_PATH=./out
INCDIR += -I./inc
INCDIR += -I./inc/libtom
INCDIR += -I./inc/mbedtls
INCDIR += -I./customer_api_wrapper

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

#source
SRCS += $(wildcard src/*.c)
SRCS += $(wildcard src/sec_api/*.c)
SRCS += $(wildcard customer_api_wrapper/*.c)

LIBS += -ltomcrypt
LIBS += -lmbedcrypto -lmbedtls -lmbedx509

# object
OBJS := $(SRCS:.c=.o)
SUS := $(SRCS:.c=.su)

all: $(BIN) $(TARGET) $(USER_APP)

$(USER_APP): $(TARGET)
	@echo "  Build User Source :"
	cd $(USER_APP_PATH) && $(CC) $(CFLAGS) -I./ -I../customer_api_wrapper -c user_app.c && cd ..
	@echo "  Gen User Lib :"
	$(Q)$(AR) -rcs user_app/lib$(USER_APP).a $(USER_APP_PATH)/user_app.o
	$(Q)cp $(USER_APP_PATH)/lib$(USER_APP).a ./out/lib$(USER_APP).a
	@echo "  Build User Source :"
	$(Q)$(CC) $(CFLAGS) -o $(OUTPUT_PATH)/$@ $(USER_APP_PATH)/main.c -I$(USER_APP_PATH) $(LDFLAGS) $(LDLIBS) -L$(OUTPUT_PATH) -l$(USER_APP) -l$(TARGET) $(LIBS)
	mkdir -p $(RELEASE_PACKAGE)
	cp -r ./out/lib$(USER_APP).a $(RELEASE_PACKAGE)/lib$(USER_APP).a
	cp -r $(USER_APP_PATH)/user_app.h  $(RELEASE_PACKAGE)/user_app.h

$(BIN): $(TARGET)
	@echo "  Build $(BIN) :"
	$(Q)$(CC) $(CFLAGS) -o $(OUTPUT_PATH)/$@ test/main.c $(LDFLAGS) $(LDLIBS) -L$(OUTPUT_PATH) -l$(TARGET)  $(LIBS)
	@echo "  Build $(BIN)_suite :"
	$(Q)$(CC) $(CFLAGS) -o $(OUTPUT_PATH)/$@_suite test/test_app.c $(LDFLAGS) $(LDLIBS) -L$(OUTPUT_PATH) -l$(TARGET) $(LIBS)

$(TARGET): $(OBJS)
	@echo "   object (.o) --> library(.a)"
	$(Q)mkdir $(OUTPUT_PATH)
	$(Q)$(AR) -rcs $(OUTPUT_PATH)/$(TARGET_LIB) $(OBJS) ./customer_api_wrapper/customization_wrapper.o
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
	$(Q)rm -rf $(USER_APP_PATH)/*.o
	$(Q)rm -rf $(USER_APP_PATH)/*.su
	$(Q)rm -rf $(USER_APP_PATH)/*.a
	cd customer_app_template/cust_app_dev && make clean
