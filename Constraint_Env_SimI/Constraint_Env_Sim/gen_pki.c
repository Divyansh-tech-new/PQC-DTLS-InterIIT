#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/asn.h>

/* OID: 2.16.840.1.101.3.4.3.17 (Dilithium2 / ML-DSA-44) */
static const unsigned char DILITHIUM_OID[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11 };

/* Helper: Write variable length */
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

/* Helper: Save buffer to file */
int save_file(const char* fname, const unsigned char* buf, int len) {
    FILE* f = fopen(fname, "wb");
    if (!f) return -1;
    fwrite(buf, 1, len, f);
    fclose(f);
    printf("Wrote %s (%d bytes)\n", fname, len);
    return 0;
}

/* 
 * Generate a Self-Signed CA Cert
 * Returns 0 on success
 */
int gen_ca(dilithium_key* key, const char* certFile) {
    WC_RNG rng;
    wc_InitRng(&rng);

    // 1. Context and TBS
    unsigned char tbs[10000];
    unsigned char* b = tbs;
    
    // Explicit Tag [0] Version 3 (02)
    // 0A0 03 02 01 02
    *b++ = 0xA0; *b++ = 0x03; *b++ = 0x02; *b++ = 0x01; *b++ = 0x02;
    
    // Serial Number
    *b++ = 0x02; *b++ = 0x08;
    wc_RNG_GenerateBlock(&rng, b, 8); b += 8;
    
    // Sig Alg ID
    *b++ = 0x30; *b++ = 0x0B;
    memcpy(b, DILITHIUM_OID, sizeof(DILITHIUM_OID)); b += sizeof(DILITHIUM_OID);
    
    // Issuer: CN=PQC Root CA
    // Sequence { Set { Seq { OID(CN), PrintableString("PQC Root CA") } } }
    // 30 14 31 12 30 10 06 03 55 04 03 13 09 'P' ...
    const unsigned char name[] = {
        0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x09,
        'P', 'Q', 'C', ' ', 'R', 'o', 'o', 't', ' '
    };
    memcpy(b, name, sizeof(name)); b += sizeof(name);
    
    // Validity
    const unsigned char validity[] = {
        0x30, 0x1E, 
        0x17, 0x0D, '2', '4', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
        0x17, 0x0D, '3', '0', '1', '2', '3', '1', '2', '3', '5', '9', '5', '9', 'Z'
    };
    memcpy(b, validity, sizeof(validity)); b += sizeof(validity);
    
    // Subject (Same as Issuer)
    memcpy(b, name, sizeof(name)); b += sizeof(name);
    
    // SPKI
    // Seq { Seq { OID }, BitString { 00 + PubKey } }
    unsigned char pubRaw[5000];
    word32 pubRawSz = sizeof(pubRaw);
    wc_dilithium_export_public(key, pubRaw, &pubRawSz);
    
    unsigned char spki[6000];
    unsigned char* s = spki;
    *s++ = 0x30; *s++ = 0x0B; // Alg
    memcpy(s, DILITHIUM_OID, sizeof(DILITHIUM_OID)); s += sizeof(DILITHIUM_OID);
    
    *s++ = 0x03; // BitString
    write_len(&s, 1 + pubRawSz);
    *s++ = 0x00; // unused
    memcpy(s, pubRaw, pubRawSz); s += pubRawSz;
    int spkiLen = s - spki;
    
    // Wrap SPKI in Seq
    *b++ = 0x30;
    write_len(&b, spkiLen);
    memcpy(b, spki, spkiLen); b+= spkiLen;

    /* Extensions for CA: BasicConstraints = CA:TRUE */
    /* Extension: 2.5.29.19 (BasicConstraints) */
    /* Seq { OID, Critical(TRUE), OctetString(Seq{CA=TRUE}) } */
    /* OID: 55 1D 13 */
    /* basicConstraints: 30 03 01 01 FF (CA=True) */
    /* wrapped in OctetString: 04 05 30 03 01 01 FF */
    /* critical: 01 01 FF */
    /* Entire Ext: 30 0F 06 03 55 1D 13 01 01 FF 04 05 30 03 01 01 FF */
    
    // Extensions Wrapper: [3] Explicit -> Sequence
    // Let's add it.
    // Extensions Wrapper: [3] Explicit -> SEQUENCE (List) -> SEQUENCE (Extension)
    unsigned char ext[] = {
        0xA3, 0x13, // [3] Len 19
        0x30, 0x11, // SEQUENCE (List) Len 17
        0x30, 0x0F, // SEQUENCE (Extension) Len 15
        0x06, 0x03, 0x55, 0x1D, 0x13, 
        0x01, 0x01, 0xFF, 
        0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF
    };
    memcpy(b, ext, sizeof(ext)); b += sizeof(ext);

    // TBS Header
    unsigned char tbsParams[100];
    unsigned char* p = tbsParams;
    *p++ = 0x30;
    write_len(&p, b - tbs);
    
    // Signature
    unsigned char sig[5000];
    word32 sigSz = sizeof(sig);
    
    // Hash TBS manually? No, wolfSSL does it?
    // We need to concat header + body for signing
    int tbsTotalLen = (p-tbsParams) + (b-tbs);
    unsigned char* fullTbs = malloc(tbsTotalLen);
    memcpy(fullTbs, tbsParams, p-tbsParams);
    memcpy(fullTbs + (p-tbsParams), tbs, b-tbs);
    
    if (wc_dilithium_sign_msg(fullTbs, tbsTotalLen, sig, &sigSz, key, &rng) != 0) {
        printf("CA Sign failed\n"); free(fullTbs); return -1;
    }
    
    // Final Cert
    unsigned char cert[10000];
    unsigned char* c = cert;
    *c++ = 0x30; // Seq
    
    // Suffix: AlgId + BitStr(Sig)
    unsigned char suffix[6000];
    unsigned char* sf = suffix;
    *sf++ = 0x30; *sf++ = 0x0B;
    memcpy(sf, DILITHIUM_OID, sizeof(DILITHIUM_OID)); sf += sizeof(DILITHIUM_OID);
    *sf++ = 0x03;
    write_len(&sf, 1 + sigSz);
    *sf++ = 0x00;
    memcpy(sf, sig, sigSz); sf += sigSz;
    int suffixLen = sf - suffix;
    
    int total = tbsTotalLen + suffixLen;
    write_len(&c, total);
    
    FILE* f = fopen(certFile, "wb");
    fwrite(cert, 1, c-cert, f);
    fwrite(fullTbs, 1, tbsTotalLen, f);
    fwrite(suffix, 1, suffixLen, f);
    fclose(f);
    printf("Generated CA: %s\n", certFile);
    
    free(fullTbs);
    return 0;
}

/*
 * Generate Entity Cert (Server or Client) signed by CA Key
 */
int gen_entity(dilithium_key* entityKey, dilithium_key* caKey, const char* nameStr, const char* certFile) {
    WC_RNG rng;
    wc_InitRng(&rng);

    unsigned char tbs[10000];
    unsigned char* b = tbs;
    
    *b++ = 0xA0; *b++ = 0x03; *b++ = 0x02; *b++ = 0x01; *b++ = 0x02;
    *b++ = 0x02; *b++ = 0x08;
    wc_RNG_GenerateBlock(&rng, b, 8); b += 8;
    
    *b++ = 0x30; *b++ = 0x0B;
    memcpy(b, DILITHIUM_OID, sizeof(DILITHIUM_OID)); b += sizeof(DILITHIUM_OID);
    
    // Issuer (Must match CA Subject EXACTLY)
    const unsigned char issuer[] = {
        0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x09,
        'P', 'Q', 'C', ' ', 'R', 'o', 'o', 't', ' '
    };
    memcpy(b, issuer, sizeof(issuer)); b += sizeof(issuer);
    
    const unsigned char validity[] = {
        0x30, 0x1E, 
        0x17, 0x0D, '2', '4', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
        0x17, 0x0D, '3', '0', '1', '2', '3', '1', '2', '3', '5', '9', '5', '9', 'Z'
    };
    memcpy(b, validity, sizeof(validity)); b += sizeof(validity);
    
    // Subject
    // Seq { Set { Seq { OID(CN), PrintableString(Name) } } }
    unsigned char subject[100];
    unsigned char* sbuf = subject;
    *sbuf++ = 0x30; *sbuf++ = 0x00; // Len placeholder
    *sbuf++ = 0x31; *sbuf++ = 0x00;
    *sbuf++ = 0x30; *sbuf++ = 0x00;
    *sbuf++ = 0x06; *sbuf++ = 0x03; *sbuf++ = 0x55; *sbuf++ = 0x04; *sbuf++ = 0x03; // CN
    *sbuf++ = 0x13; 
    int nLen = strlen(nameStr);
    *sbuf++ = nLen;
    memcpy(sbuf, nameStr, nLen); sbuf += nLen;
    // Fix lens
    subject[1] = (sbuf - subject) - 2;
    subject[3] = (sbuf - subject) - 4;
    subject[5] = (sbuf - subject) - 6;
    memcpy(b, subject, sbuf - subject); b += (sbuf - subject);

    // SPKI
    unsigned char pubRaw[5000];
    word32 pubRawSz = sizeof(pubRaw);
    wc_dilithium_export_public(entityKey, pubRaw, &pubRawSz);
    
    unsigned char spki[6000];
    unsigned char* s = spki;
    *s++ = 0x30; *s++ = 0x0B;
    memcpy(s, DILITHIUM_OID, sizeof(DILITHIUM_OID)); s += sizeof(DILITHIUM_OID);
    *s++ = 0x03;
    write_len(&s, 1 + pubRawSz);
    *s++ = 0x00;
    memcpy(s, pubRaw, pubRawSz); s += pubRawSz;
    int spkiLen = s - spki;
    
    *b++ = 0x30;
    write_len(&b, spkiLen);
    memcpy(b, spki, spkiLen); b+= spkiLen;

    // TBS Header
    unsigned char tbsParams[100];
    unsigned char* p = tbsParams;
    *p++ = 0x30;
    write_len(&p, b - tbs);
    
    // Sign with CA Key
    unsigned char sig[5000];
    word32 sigSz = sizeof(sig);
    int tbsTotalLen = (p-tbsParams) + (b-tbs);
    unsigned char* fullTbs = malloc(tbsTotalLen);
    memcpy(fullTbs, tbsParams, p-tbsParams);
    memcpy(fullTbs + (p-tbsParams), tbs, b-tbs);
    
    if (wc_dilithium_sign_msg(fullTbs, tbsTotalLen, sig, &sigSz, caKey, &rng) != 0) {
        printf("Entity Sign failed\n"); free(fullTbs); return -1;
    }

    // Final Cert
    unsigned char cert[10000];
    unsigned char* c = cert;
    *c++ = 0x30;
    
    unsigned char suffix[6000];
    unsigned char* sf = suffix;
    *sf++ = 0x30; *sf++ = 0x0B;
    memcpy(sf, DILITHIUM_OID, sizeof(DILITHIUM_OID)); sf += sizeof(DILITHIUM_OID);
    *sf++ = 0x03;
    write_len(&sf, 1 + sigSz);
    *sf++ = 0x00;
    memcpy(sf, sig, sigSz); sf += sigSz;
    int suffixLen = sf - suffix;
    
    int total = tbsTotalLen + suffixLen;
    write_len(&c, total);
    
    FILE* f = fopen(certFile, "wb");
    fwrite(cert, 1, c-cert, f);
    fwrite(fullTbs, 1, tbsTotalLen, f);
    fwrite(suffix, 1, suffixLen, f);
    fclose(f);
    printf("Generated: %s\n", certFile);
    free(fullTbs);
    return 0;
}

int save_key_asn1(dilithium_key* key, const char* fname) {
    unsigned char output[5000];
    word32 outLen = sizeof(output);
    int ret = wc_Dilithium_PrivateKeyToDer(key, output, outLen);
    if (ret <= 0) return -1;
    return save_file(fname, output, ret);
}

int main() {
    WC_RNG rng;
    wc_InitRng(&rng);
    
    dilithium_key caKey, servKey, cliKey;
    wc_dilithium_init(&caKey); wc_dilithium_set_level(&caKey, WC_ML_DSA_44);
    wc_dilithium_init(&servKey); wc_dilithium_set_level(&servKey, WC_ML_DSA_44);
    wc_dilithium_init(&cliKey); wc_dilithium_set_level(&cliKey, WC_ML_DSA_44);
    
    printf("Generating Keys...\n");
    wc_dilithium_make_key(&caKey, &rng);
    wc_dilithium_make_key(&servKey, &rng);
    wc_dilithium_make_key(&cliKey, &rng);
    
    printf("Saving Keys...\n");
    save_key_asn1(&caKey, "pqc_certs/ca-key.der");
    save_key_asn1(&servKey, "pqc_certs/server-key-asn1.der");
    save_key_asn1(&cliKey, "pqc_certs/client-key-asn1.der");
    
    printf("Generating Certs...\n");
    gen_ca(&caKey, "pqc_certs/ca-cert-final.der");
    gen_entity(&servKey, &caKey, "Server", "pqc_certs/server-cert-final.der");
    gen_entity(&cliKey, &caKey, "Client", "pqc_certs/client-cert-final.der");
    
    wc_dilithium_free(&caKey);
    wc_dilithium_free(&servKey);
    wc_dilithium_free(&cliKey);
    return 0;
}
