# toolchain setting]
TOOLCHAIN_PREFIX=riscv32-corev-elf
CC=$(TOOLCHAIN_PREFIX)-gcc
LD=$(TOOLCHAIN_PREFIX)-ld
AR=$(TOOLCHAIN_PREFIX)-ar

TARGET     = MyLib
TARGET_LIB = lib$(TARGET).a
BIN        = demo

O=./out
INCDIR += -I./inc 
INCDIR += -I./inc/libtom 
INCDIR += -I./inc/mbedtls

CFLAGS += $(INCDIR)
LDFLAGS +=

LDLIBS += -L./lib/libtom/$(TOOLCHAIN_PREFIX)
LDLIBS += -L./lib/mbedtls/$(TOOLCHAIN_PREFIX)

srcs += add.c
srcs += libtom_test.c
srcs += mbedtls_test.c

LIBS += -ltomcrypt
LIBS += -lmbedcrypto -lmbedtls -lmbedx509

objs := $(patsubst %.c,$(O)/%.o, $(srcs))

all: $(BIN) $(TARGET)

$(BIN): $(TARGET)
	@echo "  Build $@ :"
	$(CC) $(CFLAGS) -o $(O)/$@ test/main.c $(LDFLAGS) $(LDLIBS) -L$(O) -l$(TARGET)  $(LIBS)

$(TARGET): $(objs)
	@echo "   object (.o) --> library(.a)"
	$(AR) -rsc $(O)/$(TARGET_LIB) $(O)/*.o

$(O)/%.o: src/%.c
	@mkdir -p $(O)
	@echo "   CC   $<"
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo 'CLEAN $(O)'
	$(Q)rm -rf $(O)

