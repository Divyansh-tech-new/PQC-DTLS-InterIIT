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
