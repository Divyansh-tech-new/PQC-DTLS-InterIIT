/*
 * PQC Certificate Key Generator
 * Generates Dilithium keys for CA, Server, and Client
 * For use in DTLS 1.3 mutual authentication
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// WolfSSL headers
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define DILITHIUM_LEVEL WC_ML_DSA_44  /* ML-DSA-44 (Dilithium Level 2) */
#define MAX_KEY_SIZE 4096

typedef struct {
    const char* name;
    const char* priv_file;
    const char* pub_file;
} KeyPair;

int generate_keypair(WC_RNG* rng, const KeyPair* kp) {
    dilithium_key key;
    byte priv[MAX_KEY_SIZE];
    byte pub[MAX_KEY_SIZE];
    word32 privSz = MAX_KEY_SIZE;
    word32 pubSz = MAX_KEY_SIZE;
    FILE* fp;
    int ret;

    printf("\n[*] Generating %s keypair...\n", kp->name);

    /* Initialize Dilithium key */
    ret = wc_dilithium_init(&key);
    if (ret != 0) {
        printf("ERROR: wc_dilithium_init failed: %d\n", ret);
        return ret;
    }

    /* Set security level (ML-DSA-44 = Level 2) */
    ret = wc_dilithium_set_level(&key, DILITHIUM_LEVEL);
    if (ret != 0) {
        printf("ERROR: wc_dilithium_set_level failed: %d\n", ret);
        wc_dilithium_free(&key);
        return ret;
    }

    /* Generate key pair */
    ret = wc_dilithium_make_key(&key, rng);
    if (ret != 0) {
        printf("ERROR: wc_dilithium_make_key failed: %d\n", ret);
        wc_dilithium_free(&key);
        return ret;
    }

    /* Export private key */
    ret = wc_dilithium_export_private(&key, priv, &privSz);
    if (ret != 0) {
        printf("ERROR: wc_dilithium_export_private failed: %d\n", ret);
        wc_dilithium_free(&key);
        return ret;
    }

    /* Export public key */
    ret = wc_dilithium_export_public(&key, pub, &pubSz);
    if (ret != 0) {
        printf("ERROR: wc_dilithium_export_public failed: %d\n", ret);
        wc_dilithium_free(&key);
        return ret;
    }

    /* Write private key */
    fp = fopen(kp->priv_file, "wb");
    if (!fp) {
        printf("ERROR: Cannot open %s for writing\n", kp->priv_file);
        wc_dilithium_free(&key);
        return -1;
    }
    fwrite(priv, 1, privSz, fp);
    fclose(fp);
    printf("  ✓ Private key: %s (%u bytes)\n", kp->priv_file, privSz);

    /* Write public key */
    fp = fopen(kp->pub_file, "wb");
    if (!fp) {
        printf("ERROR: Cannot open %s for writing\n", kp->pub_file);
        wc_dilithium_free(&key);
        return -1;
    }
    fwrite(pub, 1, pubSz, fp);
    fclose(fp);
    printf("  ✓ Public key: %s (%u bytes)\n", kp->pub_file, pubSz);

    wc_dilithium_free(&key);
    return 0;
}

int main(int argc, char** argv) {
    WC_RNG rng;
    int ret;
    
    KeyPair keys[] = {
        {"CA (Certificate Authority)", "pqc_certs/ca-key.der", "pqc_certs/ca-pub.der"},
        {"Server", "pqc_certs/server-key.der", "pqc_certs/server-pub.der"},
        {"Client (RISC-V Device)", "pqc_certs/client-key.der", "pqc_certs/client-pub.der"}
    };
    int num_keys = sizeof(keys) / sizeof(keys[0]);

    printf("========================================\n");
    printf("PQC Key Generation (Dilithium ML-DSA-44)\n");
    printf("========================================\n");

    /* Create output directory */
    system("mkdir -p pqc_certs");

    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("ERROR: wc_InitRng failed: %d\n", ret);
        return -1;
    }

    /* Generate all keypairs */
    for (int i = 0; i < num_keys; i++) {
        ret = generate_keypair(&rng, &keys[i]);
        if (ret != 0) {
            printf("ERROR: Failed to generate %s\n", keys[i].name);
            wc_FreeRng(&rng);
            return -1;
        }
    }

    wc_FreeRng(&rng);

    printf("\n========================================\n");
    printf("✓ All keys generated successfully!\n");
    printf("========================================\n");
    printf("\nGenerated files in pqc_certs/:\n");
    printf("  - ca-key.der, ca-pub.der\n");
    printf("  - server-key.der, server-pub.der\n");
    printf("  - client-key.der, client-pub.der\n");
    printf("\nSecurity: Dilithium Level 2 (ML-DSA-44)\n");
    printf("NIST Security Level: 2 (equivalent to AES-128)\n");
    printf("\nNext step: Run ./embed_certs.sh to create C header files\n");

    return 0;
}
