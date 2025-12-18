BUILD_DIR?=../build/sim_sp/
include $(BUILD_DIR)/software/include/generated/variables.mak
SOC_DIRECTORY=/home/neginegi/psI/82_PQC_DTLS_PS/Constraint_Env_SimI/Constraint_Env_Sim/litex/litex/soc
$(info DEBUG: Force SOC_DIRECTORY is [$(SOC_DIRECTORY)])
include $(SOC_DIRECTORY)/software/common.mak

# Use LOCAL wolfSSL sources (consistent with local headers)
WOLFSSL_ROOT = /home/neginegi/projects/ps/wolfssl

# 1. WolfSSL TLS Layer Sources (absolute paths to pre-compiled .o files)
WOLFSSL_TLS_OBJS := $(wildcard $(WOLFSSL_ROOT)/src/*.o)
WOLFSSL_TLS_OBJS := $(filter-out $(WOLFSSL_ROOT)/src/conf.o, $(WOLFSSL_TLS_OBJS))
WOLFSSL_TLS_OBJS := $(filter-out $(WOLFSSL_ROOT)/src/ssl_sk.o, $(WOLFSSL_TLS_OBJS))

# 2. WolfCrypt Crypto Layer Sources (absolute paths to pre-compiled .o files)
WOLFSSL_CRYPTO_OBJS := $(wildcard $(WOLFSSL_ROOT)/wolfcrypt/src/*.o)

# 3. Application Sources
OBJECTS  = crt0.o main.o
# wrap_mlkem.o excluded for non-PQC testing

# 4. Combine all objects (local + absolute paths to wolfSSL)
ALL_OBJS = $(OBJECTS) $(WOLFSSL_TLS_OBJS) $(WOLFSSL_CRYPTO_OBJS)

# Linker Wrapper for PQC KeyGen Bypass
LDFLAGS += -Wl,--wrap=wc_MlKemKey_MakeKey

# 4. Include Paths
INC  = -I.
INC += -I./wolfssl/wolfcrypt
INC += -I./wolfssl
INC += -I$(WOLFSSL_ROOT)
INC += -I$(WOLFSSL_ROOT)/wolfcrypt

# 5. Compiler Flags
# NOTE: Removed -DWOLFSSL_DTLS_CH_FRAG (already in user_settings.h)
CFLAGS += $(INC)
CFLAGS += -DWOLFSSL_USER_SETTINGS
CFLAGS += -DHAVE_RPK

all: boot.bin

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@
ifneq ($(OS),Windows_NT)
	chmod -x $@
endif

vpath %.a $(PACKAGES:%=../%)

boot.elf: $(OBJECTS)
	@echo "Linking with wolfSSL objects from: $(WOLFSSL_ROOT)"
	@echo "  TLS objects: $(words $(WOLFSSL_TLS_OBJS)) files"
	@echo "  Crypto objects: $(words $(WOLFSSL_CRYPTO_OBJS)) files"
	$(CC) $(LDFLAGS) -T linker.ld -N -o $@ \
		$(ALL_OBJS) \
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

VPATH = $(BIOS_DIRECTORY):$(BIOS_DIRECTORY)/cmds:$(CPU_DIRECTORY):$(WOLFSSL_ROOT)/src:$(WOLFSSL_ROOT)/wolfcrypt/src

%.o: %.cpp
	$(compilexx)

%.o: %.c
	$(compile)
donut.o: CFLAGS += -w

VPATH = $(BIOS_DIRECTORY):$(BIOS_DIRECTORY)/cmds:$(CPU_DIRECTORY)

%.o: %.cpp
	$(RM) $(OBJECTS) boot.elf boot.bin .*~ *~

.PHONY: all clean

TEST_OBJECTS = crt0.o test_hello.o

test_hello.elf: $(TEST_OBJECTS)
	$(CC) $(LDFLAGS) -T linker.ld -N -o $@ \
		$(TEST_OBJECTS) \
		$(PACKAGES:%=-L$(BUILD_DIR)/software/%) \
		-Wl,--whole-archive \
		-Wl,--gc-sections \
		-Wl,-Map,$@.map \
		$(LIBS:lib%=-l%)

ifneq ($(OS),Windows_NT)
	chmod -x $@
endif
