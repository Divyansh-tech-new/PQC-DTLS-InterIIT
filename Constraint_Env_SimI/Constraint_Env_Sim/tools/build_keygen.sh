#!/bin/bash

# Compile and run the PQC key generator
# This creates Dilithium keypairs for CA, Server, and Client

set -e

echo "Building PQC key generator..."

# Compile with wolfSSL
gcc -o tools/generate_pqc_keys \
    tools/generate_pqc_keys.c \
    -I./boot/wolfssl \
    -I./boot \
    -L./boot -lwolfssl \
    -DWOLFSSL_USER_SETTINGS \
    -lm

echo "Running key generator..."
./tools/generate_pqc_keys

echo ""
echo "Done! Keys are in pqc_certs/"
