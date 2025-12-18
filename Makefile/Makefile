BUILD_DIR?=../build/
include $(BUILD_DIR)/software/include/generated/variables.mak
include $(SOC_DIRECTORY)/software/common.mak

# 1. WolfSSL TLS Layer Sources
# Exclude files that are included by ssl.c
SRC_FILES := $(wildcard src/*.c)
SRC_FILES := $(filter-out src/conf.c, $(SRC_FILES))
SRC_FILES := $(filter-out src/ssl_sk.c, $(SRC_FILES))
SRCS += $(SRC_FILES)

# 2. WolfCrypt Crypto Layer Sources
SRCS += $(wildcard wolfcrypt/src/*.c)

# 3. Application Sources
OBJECTS  = crt0.o main.o time_port.o
OBJECTS += $(SRCS:.c=.o)

# 4. Include Paths
INC  = -I.
INC += -I./wolfssl
INC += -I./wolfssl/wolfcrypt

# 5. Compiler Flags
# NOTE: Removed -DWOLFSSL_DTLS_CH_FRAG (already in user_settings.h)
CFLAGS += $(INC)
CFLAGS += -DWOLFSSL_USER_SETTINGS

all: boot.bin

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@
ifneq ($(OS),Windows_NT)
	chmod -x $@
endif

vpath %.a $(PACKAGES:%=../%)

boot.elf: $(OBJECTS)
	$(CC) $(LDFLAGS) -T linker.ld -N -o $@ \
		$(OBJECTS) \
		$(PACKAGES:%=-L$(BUILD_DIR)/software/%) \
		-Wl,--whole-archive \
		-Wl,--gc-sections \
		-Wl,-Map,$@.map \
		$(LIBS:lib%=-l%)
ifneq ($(OS),Windows_NT)
	chmod -x $@
endif

# Dependencies
-include $(OBJECTS:.o=.d)

donut.o: CFLAGS += -w

VPATH = $(BIOS_DIRECTORY):$(BIOS_DIRECTORY)/cmds:$(CPU_DIRECTORY)

%.o: %.cpp
	$(compilexx)

%.o: %.c
	$(compile)

%.o: %.S
	$(assemble)

clean:
	$(RM) $(OBJECTS) boot.elf boot.bin .*~ *~

.PHONY: all clean
