#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/asn.h>

/* Reuse logic from wrap_cert.c for signing */
/* OID: 2.16.840.1.101.3.4.3.17 (Dilithium2 / ML-DSA-44) */
static const unsigned char DILITHIUM_OID[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11 };

void write_len(unsigned char** p, int len) {
    if (len < 128) {
        *(*p)++ = len;
    } else if (len < 256) {
        *(*p)++ = 0x81;
        *(*p)++ = len;
    } else if (len < 65536) {
        *(*p)++ = 0x82;
        *(*p)++ = (len >> 8) & 0xFF;
        *(*p)++ = len & 0xFF;
    }
}

int read_file(const char* fname, unsigned char** buf, long* sz) {
    FILE* f = fopen(fname, "rb");
    if (!f) { printf("Cannot open %s\n", fname); return -1; }
    fseek(f, 0, SEEK_END);
    *sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    *buf = (unsigned char*)malloc(*sz);
    fread(*buf, 1, *sz, f);
    fclose(f);
    return 0;
}

int sign_and_write_cert(const char* keyFile, const char* spkiFile, const char* outFile) {
    unsigned char *keyBuf, *spkiBuf;
    long keySz, spkiSz;
    
    if (read_file(keyFile, &keyBuf, &keySz) != 0) return -1;
    if (read_file(spkiFile, &spkiBuf, &spkiSz) != 0) return -1;
    
    dilithium_key key;
    wc_dilithium_init(&key);
    wc_dilithium_set_level(&key, WC_ML_DSA_44); 
    
    if (wc_dilithium_import_private(keyBuf, (word32)keySz, &key) != 0) {
        printf("Import private key failed\n"); return -1;
    }

    // Construct TBSCertificate
    unsigned char tbs[10000];
    unsigned char* p = tbs;
    unsigned char body[8000];
    unsigned char* b = body;
    
    // Version: v3 (explicit tag 0)
    memcpy(b, "\xa0\x03\x02\x01\x02", 5); b += 5;
    
    // Serial Number: 02 08 <random>
    *b++ = 0x02; *b++ = 0x08;
    memcpy(b, "\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11", 8); b += 8; // Different serial
    
    // Sig Alg
    *b++ = 0x30; *b++ = 0x0B;
    memcpy(b, DILITHIUM_OID, sizeof(DILITHIUM_OID)); b += sizeof(DILITHIUM_OID);
    
    // Issuer Name (Must match CA subject)
    // CN=Root
    const unsigned char name_root[] = {
        0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 'R', 'o', 'o', 't'
    };
    memcpy(b, name_root, sizeof(name_root)); b += sizeof(name_root);
    
    // Validity
    const unsigned char validity[] = {
        0x30, 0x1E, 
        0x17, 0x0D, '2', '4', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
        0x17, 0x0D, '3', '0', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z'
    };
    memcpy(b, validity, sizeof(validity)); b += sizeof(validity);
    
    // Subject Name: CN=Client
    const unsigned char name_client[] = {
        0x30, 0x11, 0x31, 0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x06, 'C', 'l', 'i', 'e', 'n', 't'
    };
    memcpy(b, name_client, sizeof(name_client)); b += sizeof(name_client);
    
    // SPKI Construction
    // SPKI = SEQUENCE { AlgId, BitString }
    unsigned char spki_inner[5000];
    unsigned char* si = spki_inner;
    
    // AlgId
    *si++ = 0x30; *si++ = 0x0B;
    memcpy(si, DILITHIUM_OID, sizeof(DILITHIUM_OID)); si += sizeof(DILITHIUM_OID);
    
    // BitString
    *si++ = 0x03;
    write_len(&si, 1 + spkiSz);
    *si++ = 0x00;
    memcpy(si, spkiBuf, spkiSz); si += spkiSz;
    int inner_len = si - spki_inner;
    
    // Outer Sequence for SPKI
    unsigned char spki_block[5000];
    unsigned char* s_ptr = spki_block;
    *s_ptr++ = 0x30; // Sequence
    write_len(&s_ptr, inner_len);
    memcpy(s_ptr, spki_inner, inner_len); s_ptr += inner_len;
    
    int constructed_spki_len = s_ptr - spki_block;
    
    // Copy
    memcpy(b, spki_block, constructed_spki_len); b += constructed_spki_len;
    
    // Wrap body
    unsigned char* tbs_ptr = tbs;
    *tbs_ptr++ = 0x30; 
    int body_len = b - body;
    write_len(&tbs_ptr, body_len);
    memcpy(tbs_ptr, body, body_len);
    tbs_ptr += body_len;
    int tbs_len = tbs_ptr - tbs;
    
    // Sign
    unsigned char sig[5000];
    word32 sigSz = sizeof(sig);
    WC_RNG rng;
    wc_InitRng(&rng);
    
    if (wc_dilithium_sign_msg(tbs, tbs_len, sig, &sigSz, &key, &rng) != 0) { 
        printf("Sign failed\n"); return -1; 
    }
    
    // Final Cert
    FILE* fout = fopen(outFile, "wb");
    unsigned char suffix[6000];
    unsigned char* s = suffix;
    
    // AlgId
    *s++ = 0x30; *s++ = 0x0B;
    memcpy(s, DILITHIUM_OID, sizeof(DILITHIUM_OID)); s += sizeof(DILITHIUM_OID);
    
    // Sig Value
    *s++ = 0x03; 
    write_len(&s, 1 + sigSz);
    *s++ = 0x00;
    memcpy(s, sig, sigSz); s += sigSz;
    
    int suffixLen = s - suffix;
    int total = tbs_len + suffixLen;
    
    unsigned char seqTag = 0x30;
    fwrite(&seqTag, 1, 1, fout);
    unsigned char lenBuf[4];
    unsigned char* l = lenBuf;
    write_len(&l, total);
    fwrite(lenBuf, 1, l - lenBuf, fout);
    fwrite(tbs, 1, tbs_len, fout);
    fwrite(suffix, 1, suffixLen, fout);
    fclose(fout);
    printf("Wrote %s\n", outFile);
    
    wc_dilithium_free(&key);
    free(keyBuf); free(spkiBuf);
    return 0;
}

int convert_key_to_asn1(const char* inFile, const char* outFile) {
    unsigned char *keyBuf;
    long keySz;
    
    if (read_file(inFile, &keyBuf, &keySz) != 0) return -1;
    
    dilithium_key key;
    wc_dilithium_init(&key);
    wc_dilithium_set_level(&key, WC_ML_DSA_44);
    
    if (wc_dilithium_import_private(keyBuf, (word32)keySz, &key) != 0) {
        printf("Import private key failed during conversion (sz=%ld)\n", keySz); return -1;
    }
    
    unsigned char output[5000];
    word32 outLen = sizeof(output);
    
    int ret = wc_Dilithium_PrivateKeyToDer(&key, output, outLen);
    if (ret <= 0) {
        printf("PrivateKeyToDer failed: %d\n", ret); 
        return -1;
    }
    
    FILE* f = fopen(outFile, "wb");
    fwrite(output, 1, ret, f);
    fclose(f);
    printf("Wrote %s (%u bytes)\n", outFile, outLen);
    
    wc_dilithium_free(&key);
    free(keyBuf);
    return 0;
}

int main() {
    // 1. Generate Client Cert using RAW pub key wrapped in SPKI
    // We treat "pqc_certs/client-pub.der" as the input key file.
    // Modified sign_and_write_cert to handle raw public key wrapping.
    sign_and_write_cert("pqc_certs/ca-key.der", "pqc_certs/client-pub.der", "pqc_certs/client-cert-final.der");
    
    // 2. Convert Client Key
    convert_key_to_asn1("pqc_certs/client-key.der", "pqc_certs/client-key-asn1.der");
    
    return 0;
}
