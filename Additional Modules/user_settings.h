#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

/* =========================================================================
   1. TLS / DTLS PROTOCOLS (DTLS 1.3 ONLY)
   ========================================================================= */
#define WOLFSSL_TLS13
#define WOLFSSL_DTLS
#define WOLFSSL_DTLS13

/* Disable TLS ≤ 1.2 completely (prevents fallback & signature extension failures) */
#define WOLFSSL_NO_TLS12
#define WOLFSSL_NO_TLS11
#define WOLFSSL_NO_TLS10
#define WOLFSSL_NO_TLS

/* Required DTLS 1.3 extensions */
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_EXTENDED_MASTER
#define HAVE_HKDF                 /* Required HKDF for TLS 1.3 */

/* DTLS 1.3 handshake options */
#define WOLFSSL_DTLS_ALLOW_FUTURE
#define WOLFSSL_SEND_HRR_COOKIE
#define WOLFSSL_DTLS_CH_FRAG      /* Fragmentation for large PQC keys */

/* =========================================================================
   2. EMBEDDED PLATFORM / BARE-METAL SETTINGS
   ========================================================================= */
#define WOLFSSL_USER_IO           /* Custom UART callbacks in main.c */
#define WOLFSSL_NO_SOCK           /* No BSD sockets */
#define WOLFSSL_NO_CLOCK          /* No time.h functions */
#define USER_TICKS                /* Use LowResTimer() instead of gettimeofday */
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_WOLFSSL_DIR
#define NO_MAIN_DRIVER
#define WOLFSSL_SMALL_STACK

/* Custom RNG hook */
extern int CustomRngGenerateBlock(unsigned char *, unsigned int);
#define CUSTOM_RAND_GENERATE_SEED CustomRngGenerateBlock

/* =========================================================================
   3. ENABLE POST-QUANTUM CRYPTOGRAPHY
   ========================================================================= */
/* ML-KEM for key exchange */
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM
#define WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM
#define WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM

/* Dilithium for signatures (certificate-based authentication) */
#define HAVE_DILITHIUM
#define WOLFSSL_DILITHIUM_SIGN_SMALL_MEM
#define WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM
#define WOLFSSL_DILITHIUM_NO_LARGE_CODE

/* Enable raw public key support (RFC 7250) for bare-metal */
#define HAVE_RPK

/* Certificate support */
#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_EXT

/* Hash algorithms used by PQC */
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE256
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHA256
#define WOLFSSL_SHA512

/* AEAD ciphers used in TLS 1.3 */
#define HAVE_AESGCM
#define HAVE_CHACHA
#define HAVE_POLY1305

/* =========================================================================
   4. REMOVE CLASSICAL (Pre-Quantum) CRYPTOGRAPHY
   ========================================================================= */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_ECC_DHE

/* Disable weak / legacy protocols */
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_OLD_TLS

/* =========================================================================
   5. DEBUGGING (Turn off for production)
   ========================================================================= */
// #define DEBUG_WOLFSSL
#undef NO_ERROR_STRINGS         /* Ensure error messages are printed */

/* =========================================================================
   6. HARDENING
   ========================================================================= */
#define TFM_TIMING_RESISTANT
#define WC_RSA_BLINDING         /* No effect but avoids warnings */

#endif /* USER_SETTINGS_H */
