#ifndef HOST_USER_SETTINGS_H
#define HOST_USER_SETTINGS_H

/* =========================================================================
   ENABLE POST-QUANTUM CRYPTOGRAPHY (MATCHING FIRMWARE)
   ========================================================================= */
/* ML-KEM for key exchange */
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM

/* Dilithium for signatures */
#define HAVE_DILITHIUM
#define WOLFSSL_WC_DILITHIUM
#define WOLFSSL_DILITHIUM_LEVEL2
#define WOLFSSL_EXPERIMENTAL_SETTINGS
#define WOLFSSL_DTLS_PKMATERIAL
#define HAVE_PQC

/* ECC Support (Prereq for some PQC structures) */
#define HAVE_ECC
#define HAVE_SUPPORTED_CURVES
#define HAVE_ECC256

/* TLS Extensions */
#define HAVE_TLS_EXTENSIONS

/* Certificate Generation */
#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_EXT
#define WOLFSSL_KEY_GEN

/* Hashing */
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE256
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHA256
#define WOLFSSL_SHA512

/* Disable Legacy Algorithms */
#define NO_MD5
#define NO_SHA        /* SHA-1 */
#define NO_RC4
#define NO_DSA
#define NO_DH
#define NO_DSA
#define NO_RSA
#define NO_DES3
#define NO_DES
#define NO_PWDBASED
#define NO_PKCS12

/* Disable TLS (Crypto-only build) */
#define WOLFSSL_NO_TLS12
#define WOLFSSL_NO_TLS11
#define WOLFSSL_NO_TLS10
#define WOLFSSL_NO_TLS
#define WOLFCRYPT_ONLY

/* Math Configuration */
#define WOLFSSL_SP
#define WOLFSSL_SP_SMALL
#define WOLFSSL_HAVE_SP_ECC
/* Implicitly enabled by NOT defining NO_FILESYSTEM, WOLFSSL_NO_SOCK, etc. */

/* Debugging */
// #define NO_ERROR_STRINGS
#define DEBUG_WOLFSSL

#endif /* HOST_USER_SETTINGS_H */
