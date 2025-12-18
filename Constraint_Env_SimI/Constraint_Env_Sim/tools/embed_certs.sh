#!/bin/bash

# Convert binary certificate files to C byte arrays
# For embedding in bare-metal firmware (no filesystem)

set -e

CERT_DIR="pqc_certs"
OUTPUT_DIR="boot"
OUTPUT_FILE="${OUTPUT_DIR}/pqc_certs.h"

echo "========================================="
echo "Embedding PQC Certificates as C Arrays"
echo "========================================="

if [ ! -d "$CERT_DIR" ]; then
    echo "ERROR: $CERT_DIR not found. Run generate_pqc_keys first."
    exit 1
fi

# Start writing header file
cat > "$OUTPUT_FILE" << 'HEADER_START'
/*
 * PQC Certificates - Embedded for Bare-Metal
 * Auto-generated from binary certificate files
 * 
 * Contains:
 *   - CA public key
 *   - Server private key and public key
 *   - Client private key and public key
 * 
 * All keys use Dilithium Level 2 (ML-DSA-44)
 */

#ifndef PQC_CERTS_H
#define PQC_CERTS_H

#include <wolfssl/wolfcrypt/types.h>

HEADER_START

# Function to convert binary file to C array
bin_to_c_array() {
    local filename="$1"
    local array_name="$2"
    
    if [ ! -f "$filename" ]; then
        echo "WARNING: $filename not found, skipping..."
        return
    fi
    
    echo "Converting $filename -> $array_name..."
    
    # Get file size
    local size=$(stat -f%z "$filename" 2>/dev/null || stat -c%s "$filename" 2>/dev/null)
    
    # Write array declaration
    echo "" >> "$OUTPUT_FILE"
    echo "/* $filename ($size bytes) */" >> "$OUTPUT_FILE"
    echo "static const unsigned int ${array_name}_len = $size;" >> "$OUTPUT_FILE"
    echo "static const unsigned char ${array_name}[] = {" >> "$OUTPUT_FILE"
    
    # Convert binary to hex bytes
    xxd -i < "$filename" >> "$OUTPUT_FILE"
    
    echo "};" >> "$OUTPUT_FILE"
}

# Convert all certificate files
echo ""
echo "Converting certificates..."

bin_to_c_array "${CERT_DIR}/ca-pub.der" "ca_public_key"
bin_to_c_array "${CERT_DIR}/server-key.der" "server_private_key"
bin_to_c_array "${CERT_DIR}/server-pub.der" "server_public_key"
bin_to_c_array "${CERT_DIR}/client-key.der" "client_private_key"
bin_to_c_array "${CERT_DIR}/client-pub.der" "client_public_key"

# Close header file
cat >> "$OUTPUT_FILE" << 'HEADER_END'

/*
 * Helper macros for accessing certificate data
 */
#define CA_PUB_KEY          ca_public_key
#define CA_PUB_KEY_LEN      ca_public_key_len

#define SERVER_PRIV_KEY     server_private_key
#define SERVER_PRIV_KEY_LEN server_private_key_len
#define SERVER_PUB_KEY      server_public_key
#define SERVER_PUB_KEY_LEN  server_public_key_len

#define CLIENT_PRIV_KEY     client_private_key
#define CLIENT_PRIV_KEY_LEN client_private_key_len
#define CLIENT_PUB_KEY      client_public_key
#define CLIENT_PUB_KEY_LEN  client_public_key_len

/*
 * Certificate information
 */
#define PQC_SIGNATURE_ALGORITHM "Dilithium Level 2 (ML-DSA-44)"
#define PQC_SECURITY_LEVEL      2  /* NIST Level 2 (AES-128 equivalent) */

#endif /* PQC_CERTS_H */
HEADER_END

echo ""
echo "✓ Certificate header created: $OUTPUT_FILE"
echo ""
echo "Certificate sizes:"
[ -f "${CERT_DIR}/ca-pub.der" ] && echo "  CA Public:        $(stat -f%z "${CERT_DIR}/ca-pub.der" 2>/dev/null || stat -c%s "${CERT_DIR}/ca-pub.der") bytes"
[ -f "${CERT_DIR}/server-key.der" ] && echo "  Server Private:   $(stat -f%z "${CERT_DIR}/server-key.der" 2>/dev/null || stat -c%s "${CERT_DIR}/server-key.der") bytes"
[ -f "${CERT_DIR}/server-pub.der" ] && echo "  Server Public:    $(stat -f%z "${CERT_DIR}/server-pub.der" 2>/dev/null || stat -c%s "${CERT_DIR}/server-pub.der") bytes"
[ -f "${CERT_DIR}/client-key.der" ] && echo "  Client Private:   $(stat -f%z "${CERT_DIR}/client-key.der" 2>/dev/null || stat -c%s "${CERT_DIR}/client-key.der") bytes"
[ -f "${CERT_DIR}/client-pub.der" ] && echo "  Client Public:    $(stat -f%z "${CERT_DIR}/client-pub.der" 2>/dev/null || stat -c%s "${CERT_DIR}/client-pub.der") bytes"

echo ""
echo "You can now include this in your firmware:"
echo "  #include \"pqc_certs.h\""
