CC = gcc
CFLAGS = -Wall -I/usr/local/include
LDFLAGS = -L/usr/local/lib -lwolfssl -lm

TARGET = dtls_pqc_client
SRC = dtls_pqc_client.c

all: $(TARGET)

$(TARGET): $(SRC)
	@echo "Building DTLS 1.3 PQC Client..."
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)
	@echo "✓ Client built successfully"

clean:
	rm -f $(TARGET)

.PHONY: all clean
