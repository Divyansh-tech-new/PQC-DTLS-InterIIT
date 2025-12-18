#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

/* TESTING: Minimal DTLS configuration */
#define WOLFSSL_DTLS
#define WOLFSSL_USER_IO
#define WOLFSSL_NO_SOCK
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WRITEV
#define WOLFSSL_SMALL_STACK

/* Debug output */
#define DEBUG_WOLFSSL
#define WOLFSSL_DEBUG_MEMORY
#define WOLFSSL_LOG_PRINTF
#define WOLFSSL_CALLBACKS

extern unsigned long custom_time(unsigned long* timer);
#define XTIME(t1) custom_time((unsigned long*)(t1))

extern int CustomRngGenerateBlock(unsigned char *, unsigned int);
#define CUSTOM_RAND_GENERATE_SEED CustomRngGenerateBlock

#define WOLFSSL_SHA256
#define HAVE_AESGCM
#define HAVE_AES_CBC

#endif
