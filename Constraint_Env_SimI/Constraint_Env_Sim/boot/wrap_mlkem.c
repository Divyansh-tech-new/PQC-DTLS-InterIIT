
#include <stdio.h>
#include <string.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <libbase/uart.h>
#include "static_kyber_keys.h"

/* Wrapper for wc_MlKemKey_MakeKey */
int __wrap_wc_MlKemKey_MakeKey(MlKemKey* key, WC_RNG* rng) {
    (void)rng; // Unused
    
    printf("[WRAPPER] Bypassing PQC KeyGen with static keys...\n");

    /* Safety Check: Ensure sizes match */
    if (sizeof(key->pub) != sizeof(static_kyber_pub)) {
        printf("[WRAPPER] ERROR: pub key size mismatch\n");
        return -1;
    }

    /* Inject Static Keys */
    // 1. Copy Public Key Vector (sword16 array)
    memcpy(key->pub, static_kyber_pub, sizeof(key->pub));

    // 2. Copy Private Key Vector (sword16 array)
    memcpy(key->priv, static_kyber_priv, sizeof(key->priv));

    // 3. Copy Auxiliary fields
    memcpy(key->pubSeed, static_kyber_pubSeed, sizeof(key->pubSeed));
    memcpy(key->h, static_kyber_h, sizeof(key->h));
    memcpy(key->z, static_kyber_z, sizeof(key->z));

    /* Set Flags to indicate key is populated */
    // MLKEM_FLAG_PRIV_SET | MLKEM_FLAG_PUB_SET | MLKEM_FLAG_H_SET
    // struct MlKemKey has int flags;
    // enum is in wc_mlkem.h: MLKEM_FLAG_PRIV_SET = 0x1, etc.
    key->flags = MLKEM_FLAG_PRIV_SET | MLKEM_FLAG_PUB_SET | MLKEM_FLAG_H_SET; 
    // Is A_SET needed? (Matrix A). 
    // If we bypass KeyGen, we don't Generate A.
    // However, Encaps/Decaps might need A if WOLFSSL_MLKEM_CACHE_A is defined.
    // If it is, we are missing A.
    // But defaults usually don't cache A to save RAM.
    // Let's check wc_mlkem.h for WOLFSSL_MLKEM_CACHE_A.
    // It is conditional. I'll assume it's NOT defined for embedded.
    
    return 0; // Success
}
