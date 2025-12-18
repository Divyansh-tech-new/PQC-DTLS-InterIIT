
#include <stdio.h>
#include <stdlib.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/mlkem.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

void print_array(const char* name, const unsigned char* data, int len) {
    printf("const unsigned char %s[%d] = {\n", name, len);
    for(int i = 0; i < len; i++) {
        printf("0x%02X, ", data[i]);
        if((i+1) % 16 == 0) printf("\n");
    }
    printf("};\n");
}

int main() {
    int ret;
    MlKemKey key;
    WC_RNG rng;
    
    // Initialize wolfSSL/crypt
    wolfCrypt_Init();
    
    // Init RNG
    if ((ret = wc_InitRng(&rng)) != 0) {
        fprintf(stderr, "RNG Init failed: %d\n", ret);
        return 1;
    }
    
    // Init Key (Kyber-512 / ML-KEM-512)
    // Use WC_ML_KEM_512 again
    if ((ret = wc_MlKemKey_Init(&key, WC_ML_KEM_512, NULL, INVALID_DEVID)) != 0) {
        fprintf(stderr, "Key Init failed: %d\n", ret);
        return 1;
    }
    
    // Generate Key
    if ((ret = wc_MlKemKey_MakeKey(&key, &rng)) != 0) {
        fprintf(stderr, "KeyGen failed: %d\n", ret);
        return 1;
    }

    // Dump raw fields
    printf("#ifndef STATIC_PQC_KEYS_H\n");
    printf("#define STATIC_PQC_KEYS_H\n\n");
    
    // Helper to print bytes of an array
    #define DUMP(name, arr, sz) print_array(name, (const unsigned char*)(arr), (sz))

    DUMP("static_kyber_pub", key.pub, sizeof(key.pub));
    DUMP("static_kyber_priv", key.priv, sizeof(key.priv));
    DUMP("static_kyber_pubSeed", key.pubSeed, sizeof(key.pubSeed));
    DUMP("static_kyber_h", key.h, sizeof(key.h));
    DUMP("static_kyber_z", key.z, sizeof(key.z));
    
    printf("\n#endif\n");
    
    wc_MlKemKey_Free(&key);
    wc_FreeRng(&rng);
    wolfCrypt_Cleanup();
    return 0;
}

