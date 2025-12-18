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
