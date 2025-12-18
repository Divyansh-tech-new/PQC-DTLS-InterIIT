
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/mlkem.h>

/* Dummy definition to trigger multiple definition error */
int wc_MlKemKey_MakeKey(MlKemKey* key, WC_RNG* rng) {
    return 0;
}
