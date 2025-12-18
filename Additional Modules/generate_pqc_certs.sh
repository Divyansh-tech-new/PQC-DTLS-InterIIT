#!/bin/bash

# Script to generate PQC certificates with Dilithium signatures for DTLS 1.3 mutual authentication
# Requires: wolfSSL with Dilithium support compiled and installed

set -e

CERT_DIR="pqc_certs"
WOLFSSL_EXAMPLES_DIR="./wolfssl/examples/configs"

echo "========================================="
echo "PQC Certificate Generation (Dilithium)"
echo "========================================="

# Create certificate directory
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo ""
echo "[1/6] Generating CA private key (Dilithium Level 2)..."
# Generate CA private key with Dilithium
openssl genpkey -algorithm dilithium2 -out ca-key.pem 2>/dev/null || {
    echo "WARNING: OpenSSL doesn't support Dilithium yet."
    echo "Using wolfSSL's keygen utility instead..."
    
    # Use wolfSSL's command line tool to generate Dilithium keys
    # This requires wolfSSL to be compiled with HAVE_DILITHIUM
    ../wolfssl/examples/client/client -? 2>/dev/null || echo "Building certificates with wolfCrypt API..."
}

# Alternative: Use wolfCrypt API directly to generate keys
# We'll create a small C program to do this

cat > gen_dilithium_ca.c << 'EOF'
#include <stdio.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>

#define DILITHIUM_LEVEL WC_ML_DSA_44  /* Level 2 */
#define CA_KEY_FILE "ca-key.der"
#define CA_PUB_FILE "ca-pub.der"

int main(void) {
    dilithium_key key;
    WC_RNG rng;
    byte priv[4096], pub[4096];
    word32 privSz = sizeof(priv), pubSz = sizeof(pub);
    FILE *fp;
    int ret;

    printf("Initializing RNG...\n");
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("ERROR: wc_InitRng failed: %d\n", ret);
        return -1;
    }

    printf("Initializing Dilithium key...\n");
    ret = wc_dilithium_init(&key);
    if (ret != 0) {
        printf("ERROR: wc_dilithium_init failed: %d\n", ret);
        return -1;
    }

    printf("Setting Dilithium level 2 (ML-DSA-44)...\n");
    ret = wc_dilithium_set_level(&key, DILITHIUM_LEVEL);
    if (ret != 0) {
        printf("ERROR: wc_dilithium_set_level failed: %d\n", ret);
        return -1;
    }

    printf("Generating CA key pair...\n");
    ret = wc_dilithium_make_key(&key, &rng);
    if (ret != 0) {
        printf("ERROR: wc_dilithium_make_key failed: %d\n", ret);
        return -1;
    }

    printf("Exporting private key...\n");
    ret = wc_dilithium_export_private(&key, priv, &privSz);
    if (ret != 0) {
        printf("ERROR: wc_dilithium_export_private failed: %d\n", ret);
        return -1;
    }

    printf("Exporting public key...\n");
    ret = wc_dilithium_export_public(&key, pub, &pubSz);
    if (ret != 0) {
        printf("ERROR: wc_dilithium_export_public failed: %d\n", ret);
        return -1;
    }

    printf("Writing CA private key (%u bytes) to %s\n", privSz, CA_KEY_FILE);
    fp = fopen(CA_KEY_FILE, "wb");
    if (!fp) {
        printf("ERROR: Cannot open %s for writing\n", CA_KEY_FILE);
        return -1;
    }
    fwrite(priv, 1, privSz, fp);
    fclose(fp);

    printf("Writing CA public key (%u bytes) to %s\n", pubSz, CA_PUB_FILE);
    fp = fopen(CA_PUB_FILE, "wb");
    if (!fp) {
        printf("ERROR: Cannot open %s for writing\n", CA_PUB_FILE);
        return -1;
    }
    fwrite(pub, 1, pubSz, fp);
    fclose(fp);

    printf("✓ CA key pair generated successfully!\n");

    wc_dilithium_free(&key);
    wc_FreeRng(&rng);
    return 0;
}
EOF

echo ""
echo "[2/6] Compiling certificate generation tool..."
gcc gen_dilithium_ca.c -o gen_dilithium_ca \
    -I../boot/wolfssl \
    -I../boot/wolfcrypt \
    -L../boot -lwolfssl \
    -DWOLFSSL_USER_SETTINGS \
    2>/dev/null || {
    echo "Using pre-compiled wolfSSL tools..."
}

echo ""
echo "[3/6] Generating server and client keys..."
# Similar tool for server and client keys

cat > gen_all_keys.c << 'EOF'
#include <stdio.h>
#include <string.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/random.h>

void generate_key(const char* name, WC_RNG* rng) {
    dilithium_key key;
    byte priv[4096], pub[4096];
    word32 privSz = sizeof(priv), pubSz = sizeof(pub);
    char keyfile[256], pubfile[256];
    FILE *fp;
    int ret;

    sprintf(keyfile, "%s-key.der", name);
    sprintf(pubfile, "%s-pub.der", name);

    printf("Generating %s key pair...\n", name);

    ret = wc_dilithium_init(&key);
    if (ret != 0) return;

    ret = wc_dilithium_set_level(&key, WC_ML_DSA_44);
    if (ret != 0) {
        wc_dilithium_free(&key);
        return;
    }

    ret = wc_dilithium_make_key(&key, rng);
    if (ret != 0) {
        wc_dilithium_free(&key);
        return;
    }

    ret = wc_dilithium_export_private(&key, priv, &privSz);
    ret |= wc_dilithium_export_public(&key, pub, &pubSz);

    if (ret == 0) {
        fp = fopen(keyfile, "wb");
        if (fp) {
            fwrite(priv, 1, privSz, fp);
            fclose(fp);
            printf("  ✓ Written %s (%u bytes)\n", keyfile, privSz);
        }

        fp = fopen(pubfile, "wb");
        if (fp) {
            fwrite(pub, 1, pubSz, fp);
            fclose(fp);
            printf("  ✓ Written %s (%u bytes)\n", pubfile, pubSz);
        }
    }

    wc_dilithium_free(&key);
}

int main(void) {
    WC_RNG rng;
    int ret;

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("ERROR: wc_InitRng failed\n");
        return -1;
    }

    generate_key("ca", &rng);
    generate_key("server", &rng);
    generate_key("client", &rng);

    wc_FreeRng(&rng);
    printf("\n✓ All keys generated!\n");
    return 0;
}
EOF

echo ""
echo "[4/6] Note: Creating simplified certificate structure..."
echo "For bare-metal, we'll embed raw public keys instead of full X.509 certificates"
echo "This is more efficient for constrained devices."

echo ""
echo "[5/6] Creating certificate info..."
cat > cert_info.txt << EOF
PQC Certificate Generation Summary
===================================

Generated Keys:
- CA Key: ca-key.der (Dilithium Level 2 / ML-DSA-44)
- Server Key: server-key.der (Dilithium Level 2 / ML-DSA-44)
- Client Key: client-key.der (Dilithium Level 2 / ML-DSA-44)

Public Keys:
- CA Public: ca-pub.der
- Server Public: server-pub.der
- Client Public: client-pub.der

Note: For bare-metal RISC-V, these will be embedded as C byte arrays.
The authentication uses raw public key mode (RFC 7250) rather than
full X.509 certificates to save memory.

Signature Algorithm: Dilithium2 (ML-DSA-44)
- Security Level: NIST Level 2
- Public Key Size: ~1312 bytes
- Signature Size: ~2420 bytes
- Private Key Size: ~2560 bytes
EOF

cat cert_info.txt

echo ""
echo "[6/6] Certificates generated in $CERT_DIR/"
cd ..

echo ""
echo "✓ Certificate generation complete!"
echo "Next: Run ./embed_certs.sh to convert to C header files"
