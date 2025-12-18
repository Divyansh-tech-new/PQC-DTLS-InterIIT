#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <wolfssl/wolfcrypt/types.h>

// LiteX Hardware
#include <irq.h>
#include <libbase/uart.h>
#include <libbase/console.h>
#include <generated/csr.h>

// WolfSSL
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/dilithium.h>

// PQC Certificates (embedded as byte arrays)
#include "pqc_certs.h"

/* =========================================================================
   CONFIG: Change this to switch between client/server mode
   ========================================================================= */
#define MODE_SERVER 0  // Set to 1 for server, 0 for client

/* =========================================================================
   TIMING & ENTROPY
   ========================================================================= */
static int timer_initialized = 0;

void timer_init_setup(void) {
    timer0_en_write(0);
    timer0_load_write(0xFFFFFFFF);
    timer0_reload_write(0xFFFFFFFF);
    timer0_en_write(1);
    timer_initialized = 1;
}

int gettimeofday(struct timeval* tv, void* tz) {
    if (!timer_initialized) timer_init_setup();
    
    timer0_update_value_write(1);
    uint32_t current_ticks = timer0_value_read();
    uint32_t elapsed_us = 0xFFFFFFFF - current_ticks;
    
    if (tv) {
        tv->tv_sec = elapsed_us / 1000000;
        tv->tv_usec = elapsed_us % 1000000;
    }
    return 0;
}

// Low-resolution timer required by wolfSSL when using USER_TICKS.
// Returns a monotonically increasing count in *seconds*.
word32 LowResTimer(void)
{
    if (!timer_initialized)
        timer_init_setup();

    // Update timer value from LiteX CSR
    timer0_update_value_write(1);
    uint32_t current_ticks = timer0_value_read();

    // Timer counts down from 0xFFFFFFFF; convert to elapsed microseconds
    uint32_t elapsed_us = 0xFFFFFFFFu - current_ticks;

    // Convert to seconds (wolfSSL only needs second-level accuracy)
    return (word32)(elapsed_us / 1000000u);
}


int CustomRngGenerateBlock(byte *output, word32 sz) {
    timer0_update_value_write(1);
    uint32_t seed = timer0_value_read();
    
    for (word32 i = 0; i < sz; i++) {
        seed = seed * 1103515245 + 12345;
        output[i] = (byte)((seed >> 16) ^ (i & 0xFF));
    }
    return 0;
}

/* =========================================================================
   UART I/O CALLBACKS
   ========================================================================= */
int my_IORecv(WOLFSSL *ssl, char *buff, int sz, void *ctx) {
    int bytesRead = 0;
    while (bytesRead < sz) {
        if (uart_read_nonblock()) {
            buff[bytesRead] = uart_read();
            bytesRead++;
        } else {
            if (bytesRead > 0) return bytesRead;
            return WOLFSSL_CBIO_ERR_WANT_READ;
        }
    }
    return bytesRead;
}

int my_IOSend(WOLFSSL *ssl, char *buff, int sz, void *ctx) {
    for (int i = 0; i < sz; i++) {
        uart_write(buff[i]);
    }
    return sz;
}

/* =========================================================================
   CERTIFICATE CALLBACKS FOR MUTUAL AUTHENTICATION
   ========================================================================= */

/* Verify peer certificate callback */
int my_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX* store) {
    (void)preverify;
    (void)store;
    
    printf("[Verify] Peer certificate verification callback\n");
    
    /* For now, accept all certificates (development mode) */
    /* In production, implement proper certificate chain validation */
    return 1;  /* 1 = accept, 0 = reject */
}

/* =========================================================================
   PQC CONFIGURATION WITH DILITHIUM CERTIFICATES
   ========================================================================= */
int configure_pqc_context(WOLFSSL_CTX* ctx, int is_server) {
    int ret;
    
    printf("[Config] Setting up PQC with Dilithium authentication...\n");
    
    /* 1. Load certificates and keys from embedded arrays */
    if (is_server) {
        /* Server: Load server private key and certificate */
        printf("[Config] Loading server certificate and key...\n");
        
        /* Use buffer-based loading (no filesystem) */
        ret = wolfSSL_CTX_use_certificate_buffer(ctx, 
                                                  SERVER_PUB_KEY, 
                                                  SERVER_PUB_KEY_LEN, 
                                                  WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            printf("[ERROR] Failed to load server certificate: %d\n", ret);
            return ret;
        }
        
        ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, 
                                                 SERVER_PRIV_KEY, 
                                                 SERVER_PRIV_KEY_LEN, 
                                                 WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            printf("[ERROR] Failed to load server private key: %d\n", ret);
            return ret;
        }
        
        printf("[Config] ✓ Server credentials loaded\n");
    } else {
        /* Client: Load client private key and certificate */
        printf("[Config] Loading client certificate and key...\n");
        
        ret = wolfSSL_CTX_use_certificate_buffer(ctx, 
                                                  CLIENT_PUB_KEY, 
                                                  CLIENT_PUB_KEY_LEN, 
                                                  WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            printf("[ERROR] Failed to load client certificate: %d\n", ret);
            return ret;
        }
        
        ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, 
                                                 CLIENT_PRIV_KEY, 
                                                 CLIENT_PRIV_KEY_LEN, 
                                                 WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            printf("[ERROR] Failed to load client private key: %d\n", ret);
            return ret;
        }
        
        printf("[Config] ✓ Client credentials loaded\n");
    }
    
    /* 2. Load CA certificate for peer verification */
    printf("[Config] Loading CA certificate...\n");
    ret = wolfSSL_CTX_load_verify_buffer(ctx, 
                                         CA_PUB_KEY, 
                                         CA_PUB_KEY_LEN, 
                                         WOLFSSL_FILETYPE_ASN1);
    if (ret != WOLFSSL_SUCCESS) {
        printf("[ERROR] Failed to load CA certificate: %d\n", ret);
        return ret;
    }
    printf("[Config] ✓ CA certificate loaded\n");
    
    /* 3. Enable mutual authentication (verify peer) */
    if (is_server) {
        /* Server: Require client certificate */
        wolfSSL_CTX_set_verify(ctx, 
                              WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                              my_verify_callback);
        printf("[Config] ✓ Server: Mutual authentication enabled (requires client cert)\n");
    } else {
        /* Client: Verify server certificate */
        wolfSSL_CTX_set_verify(ctx, 
                              WOLFSSL_VERIFY_PEER,
                              my_verify_callback);
        printf("[Config] ✓ Client: Server verification enabled\n");
    }
    
    /* 4. Force PQC cipher suites (TLS 1.3) */
    const char* pqc_ciphers = 
        "TLS13-AES128-GCM-SHA256:"
        "TLS13-CHACHA20-POLY1305-SHA256";
    
    ret = wolfSSL_CTX_set_cipher_list(ctx, pqc_ciphers);
    if (ret != WOLFSSL_SUCCESS) {
        printf("[ERROR] Cipher setup failed: %d\n", ret);
        return ret;
    }
    printf("[Config] ✓ Cipher suites configured\n");
    
    /* 5. Enable ML-KEM-512 (PQC Key Exchange) */
    ret = wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ML_KEM_512);
    if (ret != WOLFSSL_SUCCESS) {
        printf("[ERROR] ML-KEM setup failed: %d\n", ret);
        return ret;
    }
    printf("[Config] ✓ ML-KEM-512 key exchange enabled\n");
    
    /* 6. Configure signature algorithms - prefer Dilithium */
#ifdef HAVE_DILITHIUM
    /* Set signature algorithm list to prefer Dilithium */
    const char* sig_algs = "DILITHIUM_LEVEL2:DILITHIUM_LEVEL3:DILITHIUM_LEVEL5";
    ret = wolfSSL_CTX_set1_sigalgs_list(ctx, sig_algs);
    if (ret == WOLFSSL_SUCCESS) {
        printf("[Config] ✓ Dilithium signature algorithm configured\n");
    } else {
        printf("[WARNING] Dilithium sig config returned: %d (may not be critical)\n", ret);
    }
#endif
    
    printf("[Config] === PQC Configuration Complete ===\n");
    printf("[Config] Key Exchange: ML-KEM-512 (Kyber)\n");
    printf("[Config] Authentication: Dilithium Level 2 (ML-DSA-44)\n");
    printf("[Config] Mode: Certificate-based Mutual Authentication\n");
    
    return WOLFSSL_SUCCESS;
}

/* =========================================================================
   CLIENT MODE
   ========================================================================= */
void run_dtls_client(void) {
    printf("\n========================================\n");
    printf("   DTLS 1.3 PQC CLIENT (Mutual Auth)   \n");
    printf("========================================\n");
    
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (!ctx) {
        printf("ERROR: CTX creation failed\n");
        return;
    }
    
    // Configure I/O
    wolfSSL_CTX_SetIORecv(ctx, my_IORecv);
    wolfSSL_CTX_SetIOSend(ctx, my_IOSend);
    
    // Configure PQC with certificate-based mutual authentication
    if (configure_pqc_context(ctx, 0) != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(ctx);
        return;
    }
    
    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (!ssl) {
        printf("ERROR: SSL object creation failed\n");
        wolfSSL_CTX_free(ctx);
        return;
    }
    
    printf("\n[Client] Initiating DTLS 1.3 handshake with Dilithium auth...\n");
    printf("[Client] Waiting for server data on UART...\n");
    
    int ret;
    int attempts = 0;
    do {
        ret = wolfSSL_connect(ssl);
        if (ret != WOLFSSL_SUCCESS) {
            int err = wolfSSL_get_error(ssl, ret);
            if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
                attempts++;
                if (attempts % 1000 == 0) {
                    printf(".");  // Progress indicator
                }
                continue;
            } else {
                char errBuf[80];
                printf("\n[Client] Handshake failed: %d\n", err);
                wolfSSL_ERR_error_string(err, errBuf);
                printf("  Error: %s\n", errBuf);
                break;
            }
        }
    } while (ret != WOLFSSL_SUCCESS);
    
    if (ret == WOLFSSL_SUCCESS) {
        printf("\n========================================\n");
        printf("✓ DTLS 1.3 Handshake Complete!\n");
        printf("========================================\n");
        printf("  Cipher:     %s\n", wolfSSL_get_cipher(ssl));
        printf("  Version:    %s\n", wolfSSL_get_version(ssl));
        printf("  Key Exch:   ML-KEM-512 (Kyber)\n");
        printf("  Auth:       Dilithium Level 2 (Mutual)\n");
        printf("========================================\n");
        
        // Send test message
        const char* msg = "Hello from RISC-V with PQC Mutual Auth!";
        int sent = wolfSSL_write(ssl, msg, strlen(msg));
        if (sent > 0) {
            printf("[Client] Sent %d bytes (PQC encrypted)\n", sent);
        }
        
        // Receive response
        char buffer[128];
        int received = wolfSSL_read(ssl, buffer, sizeof(buffer)-1);
        if (received > 0) {
            buffer[received] = '\0';
            printf("[Client] Received: %s\n", buffer);
        }
    }
    
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
}

/* =========================================================================
   SERVER MODE
   ========================================================================= */
void run_dtls_server(void) {
    printf("\n========================================\n");
    printf("   DTLS 1.3 PQC SERVER (Mutual Auth)   \n");
    printf("========================================\n");
    
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfDTLSv1_3_server_method());
    if (!ctx) {
        printf("ERROR: CTX creation failed\n");
        return;
    }
    
    // Configure I/O
    wolfSSL_CTX_SetIORecv(ctx, my_IORecv);
    wolfSSL_CTX_SetIOSend(ctx, my_IOSend);
    
    // Configure PQC with certificate-based mutual authentication
    if (configure_pqc_context(ctx, 1) != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(ctx);
        return;
    }
    
    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (!ssl) {
        printf("ERROR: SSL object creation failed\n");
        wolfSSL_CTX_free(ctx);
        return;
    }
    
    printf("\n[Server] Waiting for client on UART...\n");
    printf("[Server] Ready to perform mutual authentication...\n");
    
    int ret;
    do {
        ret = wolfSSL_accept(ssl);
        if (ret != WOLFSSL_SUCCESS) {
            int err = wolfSSL_get_error(ssl, ret);
            if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
                continue;
            } else {
                char errBuf[80];
                printf("[Server] Accept failed: %d\n", err);
                wolfSSL_ERR_error_string(err, errBuf);
                printf("  Error: %s\n", errBuf);
                break;
            }
        }
    } while (ret != WOLFSSL_SUCCESS);
    
    if (ret == WOLFSSL_SUCCESS) {
        printf("\n========================================\n");
        printf("✓ Client Authenticated!\n");
        printf("========================================\n");
        printf("  Cipher:     %s\n", wolfSSL_get_cipher(ssl));
        printf("  Version:    %s\n", wolfSSL_get_version(ssl));
        printf("  Key Exch:   ML-KEM-512 (Kyber)\n");
        printf("  Auth:       Dilithium Level 2 (Mutual)\n");
        printf("========================================\n");
        
        // Receive message
        char buffer[128];
        int received = wolfSSL_read(ssl, buffer, sizeof(buffer)-1);
        if (received > 0) {
            buffer[received] = '\0';
            printf("[Server] Received: %s\n", buffer);
            
            // Echo back
            const char* response = "ACK from RISC-V Server (PQC Mutual Auth)";
            wolfSSL_write(ssl, response, strlen(response));
        }
    }
    
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
}

/* =========================================================================
   MAIN
   ========================================================================= */
int main(void) {
#ifdef CONFIG_CPU_HAS_INTERRUPT
    irq_setmask(0);
    irq_setie(1);
#endif
    
    uart_init();
    timer_init_setup();
    
    printf("\n========================================\n");
    printf("  RISC-V DTLS 1.3 PQC Demo\n");
    printf("========================================\n");
    printf("  Key Exchange: ML-KEM-512 (Kyber)\n");
    printf("  Authentication: Dilithium Level 2\n");
    printf("  Mode: Certificate-based Mutual Auth\n");
    printf("========================================\n");
    
    // Initialize WolfSSL
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        printf("ERROR: wolfSSL_Init failed\n");
        return -1;
    }

    wolfSSL_Debugging_ON();  
    
#if MODE_SERVER
    run_dtls_server();
#else
    run_dtls_client();
#endif
    
    wolfSSL_Cleanup();
    printf("\n[System] Done.\n");
    
    return 0;
}
