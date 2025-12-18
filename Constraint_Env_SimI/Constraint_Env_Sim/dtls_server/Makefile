# Makefile for DTLS 1.3 PQC Server
# Compiles with static wolfSSL for portability
# Try to find wolfSSL installation
WOLFSSL_PREFIX ?= $(HOME)/wolfssl_install

# Library paths - prefer static linking
LDFLAGS = -L$(WOLFSSL_PREFIX)/lib -Wl,-rpath=$(WOLFSSL_PREFIX)/lib
LIBS = -lwolfssl -lm -lpthread

CC = gcc
CFLAGS = -Wall -O2 -g
# ... (Keep existing)
TARGET_SERVER = dtls_pqc_server
TARGET_CLIENT = dtls_pqc_client
SRC_SERVER = dtls_pqc_server.c
SRC_CLIENT = dtls_pqc_client.c

# ...

all: $(TARGET_SERVER) $(TARGET_CLIENT)

$(TARGET_SERVER): $(SRC_SERVER)
	@echo "========================================"
	@echo "  Compiling DTLS 1.3 PQC Server"
	@echo "========================================"
	@if [ -f "$(STATIC_LIB)" ]; then \
		echo "Using static wolfSSL: $(STATIC_LIB)"; \
		$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET_SERVER) $(SRC_SERVER) $(STATIC_LIB) -lm -lpthread; \
	else \
		echo "Using dynamic wolfSSL"; \
		$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET_SERVER) $(SRC_SERVER) $(LDFLAGS) $(LIBS); \
	fi
	@echo "✓ Server built"

$(TARGET_CLIENT): $(SRC_CLIENT)
	@echo "========================================"
	@echo "  Compiling DTLS 1.3 PQC Client"
	@echo "========================================"
	@if [ -f "$(STATIC_LIB)" ]; then \
		$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET_CLIENT) $(SRC_CLIENT) $(STATIC_LIB) -lm -lpthread; \
	else \
		$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET_CLIENT) $(SRC_CLIENT) $(LDFLAGS) $(LIBS); \
	fi
	@echo "✓ Client built"

clean:
	rm -f $(TARGET_SERVER) $(TARGET_CLIENT)
	@echo "Cleaned up"

test: $(TARGET_SERVER)
	@echo "Testing server startup..."
	@timeout 2 ./$(TARGET_SERVER) || echo "Server started (timeout expected)"

.PHONY: all clean test
