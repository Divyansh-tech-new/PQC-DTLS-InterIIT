# Makefile for Hidden DTLS Helper Client

CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread
LDFLAGS = -pthread

# wolfSSL paths (adjust if needed)
WOLFSSL_PREFIX = /usr/local
WOLFSSL_INC = $(WOLFSSL_PREFIX)/include
WOLFSSL_LIB = $(WOLFSSL_PREFIX)/lib

# Include and library flags
CFLAGS += -I$(WOLFSSL_INC)
LDFLAGS += -L$(WOLFSSL_LIB) -lwolfssl -lm

TARGET = dtls_helper_client
SRC = dtls_helper_client.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo ""
	@echo "✓ Built $(TARGET)"
	@echo "  Run with: ./$(TARGET)"

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
