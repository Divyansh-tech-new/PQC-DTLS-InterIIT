#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* OID: 2.16.840.1.101.3.4.3.17 (Dilithium2 / ML-DSA-44) */
static const unsigned char DILITHIUM_OID[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11 };

/* ASN.1 Helper Functions */
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
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    *sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    *buf = (unsigned char*)malloc(*sz);
    fread(*buf, 1, *sz, f);
    fclose(f);
    return 0;
}

int sign_and_write_cert(const char* keyFile, const char* spkiFile, const char* outFile, int isCA) {
    unsigned char *keyBuf, *spkiBuf;
    long keySz, spkiSz;
    
    if (read_file(keyFile, &keyBuf, &keySz) != 0) return -1;
    if (read_file(spkiFile, &spkiBuf, &spkiSz) != 0) return -1;
    
    dilithium_key key;
    wc_dilithium_init(&key);
    wc_dilithium_set_level(&key, WC_ML_DSA_44); // Use appropriate level macro
    
    // wc_dilithium_import_private requires ONLY private key usually?
    if (wc_dilithium_import_private(keyBuf, (word32)keySz, &key) != 0) {
        printf("Import private key failed\n"); return -1;
    }

    // Construct TBSCertificate
    unsigned char tbs[10000];
    unsigned char* p = tbs;
    
    // Sequence Tag (placeholder for length)
    // We construct explicit part first then prepend length
    
    unsigned char body[8000];
    unsigned char* b = body;
    
    // Version: v3 (explicit tag 0)
    // 0xA0 03 02 01 02
    memcpy(b, "\xa0\x03\x02\x01\x02", 5); b += 5;
    
    // Serial Number: 02 08 <random>
    *b++ = 0x02; *b++ = 0x08;
    // Dummy serial: 01 02 03 ... 08
    memcpy(b, "\x01\x02\x03\x04\x05\x06\x07\x08", 8); b += 8;
    
    // Signature Algorithm: SEQUENCE { OID, NULL } (Dilithium has no params? Or NULL?)
    // rfc: id-ml-dsa-44
    // AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY DEFINED BY algorithm OPTIONAL }
    // Usually NULL params for RSA/ECDSA? PQC draft says "absent"?
    // "The parameters field MUST be absent."
    // So just SEQUENCE { OID }.
    // OID: 06 09 ...
    // Seq: 30 0B 06 09 ...
    *b++ = 0x30; *b++ = 0x0B;
    memcpy(b, DILITHIUM_OID, sizeof(DILITHIUM_OID)); b += sizeof(DILITHIUM_OID);
    
    // Issuer Name: SEQUENCE { SET { SEQUENCE { OID(CN), PrintableString("PQC Root CA") } } }
    // Helper simple name structure
    const unsigned char issuer_ca[] = {
        0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 
        'P', 'Q', 'C', ' ', 'R', 'o', 'o', 't', ' ' /* 9 bytes */
    }; 
    // Wait, let's just copy a dummy name block.
    // CN=Root
    // 30 0F 31 0D 30 0B 06 03 55 04 03 13 04 52 6f 6f 74
    const unsigned char name_root[] = {
        0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 'R', 'o', 'o', 't'
    };
    memcpy(b, name_root, sizeof(name_root)); b += sizeof(name_root);
    
    // Validity: SEQUENCE { UTCTime, UTCTime }
    // 2024 - 2030
    const unsigned char validity[] = {
        0x30, 0x1E, 
        0x17, 0x0D, '2', '4', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
        0x17, 0x0D, '3', '0', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z'
    };
    memcpy(b, validity, sizeof(validity)); b += sizeof(validity);
    
    // Subject Name
    if (isCA) {
        memcpy(b, name_root, sizeof(name_root)); b += sizeof(name_root);
    } else {
        // CN=Serv
        const unsigned char name_serv[] = {
            0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 'S', 'e', 'r', 'v'
        };
        memcpy(b, name_serv, sizeof(name_serv)); b += sizeof(name_serv);
    }
    
    // Subject Public Key Info: Copy from file!
    memcpy(b, spkiBuf, spkiSz); b += spkiSz;
    
    // Extensions (Optional) - Skip for simplicity unless needed.
    // CA BasicConstraints? Usually needed for CA verification.
    // If we skip it, maybe verify_callback returns 1 anyway?
    // Server validation might fail if CA flag missing in CA cert.
    // Let's add BasicConstraints: SEQUENCE { OID, BOOLEAN TRUE, INT pathlen }
    // But encoding extensions is annoying. 
    // "v3" requires extensions? v3 doesn't require, but CA typically has them.
    // Let's try WITHOUT extensions first.
    
    // Wrap body in Sequence = TBSCertificate
    unsigned char* tbs_ptr = tbs;
    *tbs_ptr++ = 0x30; // Sequence
    int body_len = b - body;
    write_len(&tbs_ptr, body_len);
    memcpy(tbs_ptr, body, body_len);
    tbs_ptr += body_len;
    
    int tbs_len = tbs_ptr - tbs;
    
    // Hack: wolfSSL checks trailing bytes?
    
    // Sign TBS
    unsigned char sig[5000];
    word32 sigSz = sizeof(sig);
    WC_RNG rng;
    wc_InitRng(&rng);
    
    // wc_dilithium_sign_msg(msg, msgLen, sig, sigLen, key, rng)
    int ret = wc_dilithium_sign_msg(tbs, tbs_len, sig, &sigSz, &key, &rng);
    if (ret != 0) { printf("Sign failed %d\n", ret); return -1; }
    
    // Construct Final Certificate
    unsigned char cert[10000];
    unsigned char* c = cert;
    *c++ = 0x30; // Sequence
    
    // Total Length needs calculation.
    // TBS + AlgId + BitString(Sig)
    
    // AlgId (Signature Algorithm): Same as inside TBS
    // 30 0B 06 09 ...
    int algIdLen = 2 + sizeof(DILITHIUM_OID);
    
    // Signature Value: BIT STRING
    // 03 <len> <unused_bits=0> <sig_bytes>
    int bitStrHeaderLen = (sigSz + 1 < 128) ? 2 : (sigSz + 1 < 256) ? 3 : 4;
    int sigValLen = 1 + sigSz; // 1 byte unused bits
    
    int totalLen = tbs_len + algIdLen + (1 + (sigSz+1 < 128 ? 1 : sigSz+1 < 256 ? 2 : 3) + sigSz);
    // Re-calc carefully
    
    int sigBitStringBodyLen = 1 + sigSz; 
    // Tag(1) + Len(var) + Body
    
    write_len(&c, tbs_len + algIdLen + 1 + (sigBitStringBodyLen >= 128 ? (sigBitStringBodyLen >= 256 ? 3 : 2) : 1) + sigBitStringBodyLen); // Approximate logic, just use write_len
    
    // Actually, let's write to a temp buf
    unsigned char suffix[6000];
    unsigned char* s = suffix;
    
    // AlgId
    *s++ = 0x30; *s++ = 0x0B;
    memcpy(s, DILITHIUM_OID, sizeof(DILITHIUM_OID)); s += sizeof(DILITHIUM_OID);
    
    // Sig Value
    *s++ = 0x03; // Bit String
    write_len(&s, 1 + sigSz);
    *s++ = 0x00; // 0 unused bits
    memcpy(s, sig, sigSz); s += sigSz;
    
    int suffixLen = s - suffix;
    
    // Final Write
    FILE* fout = fopen(outFile, "wb");
    unsigned char seqTag = 0x30;
    fwrite(&seqTag, 1, 1, fout);
    
    int total = tbs_len + suffixLen;
    // Write length manually to file? No, need byte array.
    unsigned char lenBuf[4];
    unsigned char* l = lenBuf;
    write_len(&l, total);
    fwrite(lenBuf, 1, l - lenBuf, fout);
    
    fwrite(tbs, 1, tbs_len, fout);
    fwrite(suffix, 1, suffixLen, fout);
    fclose(fout);
    
    printf("Wrote %s (%d bytes)\n", outFile, 1 + (int)(l-lenBuf) + total);
    return 0;
}

int main() {
    // 1. Generate CA Cert (Self-Signed)
    // Use ca-key.der (private) and ca-cert.der (public SPKI from convert_keys)
    // Wait, input SPKI file! "pqc_certs/ca-cert.der" generated by convert_keys IS SPKI!
    sign_and_write_cert("pqc_certs/ca-key.der", "pqc_certs/ca-cert.der", "pqc_certs/ca-cert-final.der", 1);
    
    // 2. Generate Server Cert (Signed by CA)
    // Use ca-key.der (private) and server-cert.der (public SPKI)
    sign_and_write_cert("pqc_certs/ca-key.der", "pqc_certs/server-cert.der", "pqc_certs/server-cert-final.der", 0);
    
    return 0;
}
