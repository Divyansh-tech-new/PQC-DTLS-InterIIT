#include <stdio.h>
#include <stdlib.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>

#define KEY_SIZE 10000 
#define CERT_BODY_SIZE 20000

int write_file(const char* fname, const byte* buf, word32 sz) {
    FILE* f = fopen(fname, "wb");
    if (!f) return -1;
    fwrite(buf, 1, sz, f);
    fclose(f);
    return 0;
}

int generate_identity(const char* name, const char* commonName, int isCA, 
                      dilithium_key* key, dilithium_key* issuerKey, 
                      const char* issuerName, WC_RNG* rng) {
    
    printf("\n--- Generating %s (%s) ---\n", name, commonName);
    
    int ret;
    byte out[KEY_SIZE];
    word32 outSz = sizeof(out);

    // 1. Generate Key
    printf("Generating Key Pair...\n");
    wc_dilithium_init(key);
    wc_dilithium_set_level(key, WC_ML_DSA_44); // Level 2
    ret = wc_dilithium_make_key(key, rng);
    if (ret != 0) { printf("MakeKey failed %d\n", ret); return ret; }

    // 2. Export Private Key (DER)
    outSz = sizeof(out);
    ret = wc_Dilithium_PrivateKeyToDer(key, out, outSz);
    if (ret < 0) { printf("PrivKeyToDer failed %d\n", ret); return ret; }
    char privName[64];
    snprintf(privName, sizeof(privName), "pqc_certs/%s-key.der", name);
    write_file(privName, out, ret);
    printf("Wrote %s (%d bytes)\n", privName, ret);

    // 3. Export Public Key (DER) - Optional but good for debug
    /*
    outSz = sizeof(out);
    ret = wc_Dilithium_PublicKeyToDer(key, out, outSz, 1);
    char pubName[64];
    snprintf(pubName, sizeof(pubName), "pqc_certs/%s-pub.der", name);
    write_file(pubName, out, ret);
    */

    // 4. Generate Certificate
    Cert cert;
    wc_InitCert(&cert);
    
    strncpy(cert.subject.country, "US", WC_CTC_NAME_SIZE);
    strncpy(cert.subject.org, "PQC Demo", WC_CTC_NAME_SIZE);
    strncpy(cert.subject.commonName, commonName, WC_CTC_NAME_SIZE);
    
    strncpy(cert.issuer.country, "US", WC_CTC_NAME_SIZE);
    strncpy(cert.issuer.org, "PQC Demo", WC_CTC_NAME_SIZE);
#define CTC_ML_DSA_LEVEL2 0x7db37aeb

    strncpy(cert.issuer.commonName, issuerName, WC_CTC_NAME_SIZE);
    
    cert.isCA = isCA;
    cert.sigType = CTC_ML_DSA_LEVEL2;
    
    // wc_MakeCert_ex uses the SUBJECT Public Key (from 'key')
    ret = wc_MakeCert_ex(&cert, out, CERT_BODY_SIZE, ML_DSA_LEVEL2_TYPE, key, rng);
    if (ret < 0) { printf("MakeCert failed %d\n", ret); return ret; }
    
    // Sign with ISSUER Private Key
    // If self-signed, issuerKey == key
    dilithium_key* signer = issuerKey ? issuerKey : key;
    
    ret = wc_SignCert_ex(cert.bodySz, cert.sigType, out, CERT_BODY_SIZE, ML_DSA_LEVEL2_TYPE, signer, rng);
    if (ret < 0) { printf("SignCert failed %d\n", ret); return ret; }
    
    int certSz = ret;
    char certName[64];
    snprintf(certName, sizeof(certName), "pqc_certs/%s-cert.der", name);
    write_file(certName, out, certSz);
    printf("Wrote %s (%d bytes)\n", certName, certSz);
    
    return 0;
}

int main() {
    int ret;
    wolfSSL_Debugging_ON();
    WC_RNG rng;
    wc_InitRng(&rng);
    
    dilithium_key caKey;
    ret = generate_identity("ca", "PQC Root CA", 1, &caKey, NULL, "PQC Root CA", &rng);
    if (ret != 0) return ret;
    
    dilithium_key srvKey;
    ret = generate_identity("server", "PQC Server", 0, &srvKey, &caKey, "PQC Root CA", &rng);
    if (ret != 0) return ret;
    
    dilithium_key cliKey;
    ret = generate_identity("client", "PQC Client", 0, &cliKey, &caKey, "PQC Root CA", &rng);
    if (ret != 0) return ret;
    
    wc_dilithium_free(&caKey);
    wc_dilithium_free(&srvKey);
    wc_dilithium_free(&cliKey);
    wc_FreeRng(&rng);
    return 0;
}
