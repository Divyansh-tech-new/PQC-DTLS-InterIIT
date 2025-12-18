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
   PSK CALLBACKS (For Pure PQC Testing)
   ========================================================================= */
static const char* psk_identity = "RISCV_PQC_Device";
static const byte psk_key[32] = {
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
    0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
};

unsigned int my_psk_client_cb(WOLFSSL* ssl, const char* hint,
                               char* identity, unsigned int id_max_len,
                               unsigned char* key, unsigned int key_max_len)
{
    (void)ssl;
    (void)hint;
    
    if (key_max_len < sizeof(psk_key)) return 0;
    
    strncpy(identity, psk_identity, id_max_len);
    memcpy(key, psk_key, sizeof(psk_key));
    
    return sizeof(psk_key);
}

unsigned int my_psk_server_cb(WOLFSSL* ssl, const char* identity,
                               unsigned char* key, unsigned int key_max_len)
{
    (void)ssl;
    
    if (strcmp(identity, psk_identity) != 0) return 0;
    if (key_max_len < sizeof(psk_key)) return 0;
    
    memcpy(key, psk_key, sizeof(psk_key));
    return sizeof(psk_key);
}

/* =========================================================================
   PQC CONFIGURATION
   ========================================================================= */
int configure_pqc_context(WOLFSSL_CTX* ctx, int is_server) {
    int ret;
    
    // 1. Set PSK callbacks (no certificates for testing)
    if (is_server) {
        wolfSSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);
        wolfSSL_CTX_use_psk_identity_hint(ctx, "RISCV_PQC_Server");
    } else {
        wolfSSL_CTX_set_psk_client_callback(ctx, my_psk_client_cb);
    }
    
    // 2. Force PQC-only cipher suites (AES-GCM with PSK)
    const char* pqc_ciphers = 
        "TLS13-AES128-GCM-SHA256:"
        "TLS13-CHACHA20-POLY1305-SHA256";
    
    ret = wolfSSL_CTX_set_cipher_list(ctx, pqc_ciphers);
    if (ret != WOLFSSL_SUCCESS) {
        printf("Cipher setup failed\n");
        return ret;
    }
    
    // 3. Enable ML-KEM-512 (PQC Key Exchange)
    ret = wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ML_KEM_512);
    if (ret != WOLFSSL_SUCCESS) {
        printf("ML-KEM setup failed: %d\n", ret);
        return ret;
    }
    
    printf("[Config] PQC Mode: ML-KEM-512 + PSK Authentication\n");
    
    return WOLFSSL_SUCCESS;
}

/* =========================================================================
   CLIENT MODE
   ========================================================================= */
void run_dtls_client(void) {
    printf("\n=== DTLS 1.3 PQC CLIENT MODE ===\n");
    
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (!ctx) {
        printf("ERROR: CTX creation failed\n");
        return;
    }
    
    // Configure I/O
    wolfSSL_CTX_SetIORecv(ctx, my_IORecv);
    wolfSSL_CTX_SetIOSend(ctx, my_IOSend);
    
    // Configure PQC
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
    
    printf("[Client] Starting DTLS handshake...\n");
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
        printf("\n[Client] ✓ Handshake Complete!\n");
        printf("  Cipher: %s\n", wolfSSL_get_cipher(ssl));
        printf("  Version: %s\n", wolfSSL_get_version(ssl));
        
        // Send test message
        const char* msg = "Hello from RISC-V PQC Client!";
        int sent = wolfSSL_write(ssl, msg, strlen(msg));
        if (sent > 0) {
            printf("[Client] Sent %d bytes (encrypted with ML-KEM)\n", sent);
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
    printf("\n=== DTLS 1.3 PQC SERVER MODE ===\n");
    
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfDTLSv1_3_server_method());
    if (!ctx) {
        printf("ERROR: CTX creation failed\n");
        return;
    }
    
    // Configure I/O
    wolfSSL_CTX_SetIORecv(ctx, my_IORecv);
    wolfSSL_CTX_SetIOSend(ctx, my_IOSend);
    
    // Configure PQC
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
    
    printf("[Server] Waiting for client on UART...\n");
    
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
        printf("[Server] ✓ Client Connected!\n");
        printf("  Cipher: %s\n", wolfSSL_get_cipher(ssl));
        printf("  Version: %s\n", wolfSSL_get_version(ssl));
        
        // Receive message
        char buffer[128];
        int received = wolfSSL_read(ssl, buffer, sizeof(buffer)-1);
        if (received > 0) {
            buffer[received] = '\0';
            printf("[Server] Received: %s\n", buffer);
            
            // Echo back
            const char* response = "ACK from RISC-V PQC Server (ML-KEM)";
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
    printf("  RISC-V DTLS 1.3 PQC Demo (ML-KEM-512) \n");
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
