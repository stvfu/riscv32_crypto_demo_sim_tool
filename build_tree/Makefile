Q=@

# toolchain setting]
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

# mbedtsl macro
CFLAGS+= -DMBEDTLS_ALLOW_PRIVATE_ACCESS

CFLAGS += $(INCDIR)
LDFLAGS +=

LDLIBS += -L./lib/libtom/$(TOOLCHAIN_PREFIX)
LDLIBS += -L./lib/mbedtls/$(TOOLCHAIN_PREFIX)

#source
SRCS += $(wildcard src/*.c)

LIBS += -ltomcrypt
LIBS += -lmbedcrypto -lmbedtls -lmbedx509

# object
OBJS := $(SRCS:.c=.o)

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

%.o: %.c
	@echo "   CC   $<"
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo '  CLEAN $(OUTPUT_PATH)'
	$(Q)rm -rf $(OBJS)
	$(Q)rm -rf $(OUTPUT_PATH)

