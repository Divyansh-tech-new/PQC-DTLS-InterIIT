#include <stdio.h>
#include <stdlib.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define KEY_SIZE 5000 
// Dilithium 2 pub=1312, priv=2560. ASN1 adds overhead. 5000 is plenty.

int convert_pub(const char* infile, const char* outfile) {
    printf("Converting Pub %s -> %s\n", infile, outfile);
    FILE* f = fopen(infile, "rb");
    if (!f) { perror("fopen in"); return -1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char* raw = malloc(sz);
    fread(raw, 1, sz, f);
    fclose(f);

    dilithium_key key;
    wc_dilithium_init(&key);
    wc_dilithium_set_level(&key, WC_ML_DSA_44); // Level 2
    
    int ret = wc_dilithium_import_public(raw, (word32)sz, &key);
    if (ret != 0) {
        printf("Import failed: %d\n", ret);
        return ret;
    }

    unsigned char der[KEY_SIZE];
    // wc_Dilithium_PublicKeyToDer(key, output, inLen, withAlg)
    // withAlg=1 means generic AlgorithmIdentifier, =0 is maybe bare? Usually 1.
    int derSz = wc_Dilithium_PublicKeyToDer(&key, der, KEY_SIZE, 1);
    if (derSz < 0) {
        printf("Export failed: %d\n", derSz);
        return derSz;
    }

    f = fopen(outfile, "wb");
    if (!f) { perror("fopen out"); return -1; }
    fwrite(der, 1, derSz, f);
    fclose(f);
    
    wc_dilithium_free(&key);
    free(raw);
    printf("Success! Size: %d\n", derSz);
    return 0;
}

int convert_priv(const char* infile, const char* outfile) {
    printf("Converting Priv %s -> %s\n", infile, outfile);
    FILE* f = fopen(infile, "rb");
    if (!f) { perror("fopen in"); return -1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char* raw = malloc(sz);
    fread(raw, 1, sz, f);
    fclose(f);

    dilithium_key key;
    wc_dilithium_init(&key);
    wc_dilithium_set_level(&key, WC_ML_DSA_44); 

    // For import_private, we need only the private part? 
    // wc_dilithium_import_private takes just private key bytes.
    // NOTE: "raw" file might be private key only OR private+public.
    // Gen_all_keys uses wc_dilithium_export_private which exports valid format.
    
    int ret = wc_dilithium_import_private(raw, (word32)sz, &key);
    if (ret != 0) {
        printf("Import failed: %d\n", ret);
        return ret;
    }

    unsigned char der[KEY_SIZE];
    // wc_Dilithium_PrivateKeyToDer(key, output, inLen)
    int derSz = wc_Dilithium_PrivateKeyToDer(&key, der, KEY_SIZE);
    if (derSz < 0) {
        printf("Export failed: %d\n", derSz);
        return derSz;
    }

    f = fopen(outfile, "wb");
    if (!f) { perror("fopen out"); return -1; }
    fwrite(der, 1, derSz, f);
    fclose(f);

    wc_dilithium_free(&key);
    free(raw);
    printf("Success! Size: %d\n", derSz);
    return 0;
}

int main() {
    convert_pub("pqc_certs/server-pub.der", "pqc_certs/server-cert.der");
    convert_priv("pqc_certs/server-key.der", "pqc_certs/server-key-asn1.der");
    convert_pub("pqc_certs/ca-pub.der", "pqc_certs/ca-cert.der");
    return 0;
}
