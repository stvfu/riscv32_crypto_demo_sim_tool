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

TARGET     = MyLib
TARGET_LIB = lib$(TARGET).a
BIN        = demo

OUTPUT_PATH=./out
INCDIR += -I./inc
INCDIR += -I./inc/libtom
INCDIR += -I./inc/mbedtls
INCDIR += -I./rot_wrapper

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
SRCS += $(wildcard rot_wrapper/*.c)

LIBS += -ltomcrypt
LIBS += -lmbedcrypto -lmbedtls -lmbedx509

# object
OBJS := $(SRCS:.c=.o)
SUS := $(SRCS:.c=.su)

all: $(BIN) $(TARGET)

$(BIN): $(TARGET)
	@echo "  Build $(BIN) :"
	$(Q)$(CC) $(CFLAGS) -o $(OUTPUT_PATH)/$@ test/main.c $(LDFLAGS) $(LDLIBS) -L$(OUTPUT_PATH) -l$(TARGET)  $(LIBS)
	@echo "  Build $(BIN)_suite :"
	$(Q)$(CC) $(CFLAGS) -o $(OUTPUT_PATH)/$@_suite test/test_app.c $(LDFLAGS) $(LDLIBS) -L$(OUTPUT_PATH) -l$(TARGET)  $(LIBS)

$(TARGET): $(OBJS)
	@echo "   object (.o) --> library(.a)"
	$(Q)mkdir $(OUTPUT_PATH)
	$(Q)$(AR) -rcs $(OUTPUT_PATH)/$(TARGET_LIB) $(OBJS)
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

