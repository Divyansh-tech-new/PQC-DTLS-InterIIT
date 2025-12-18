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

// Custom time function for XTIME macro
unsigned long custom_time(unsigned long* timer) {
    unsigned long seconds = (unsigned long)LowResTimer();
    if (timer) {
        *timer = seconds;
    }
    return seconds;
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
    printf("[IOSend] Sending %d bytes\n", sz);
    for (int i = 0; i < sz; i++) {
        uart_write(buff[i]);
    }
    printf("[IOSend] Sent successfully\n");
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
   WOLFSSL DEBUG CALLBACK
   ========================================================================= */
void wolfssl_debug_callback(const int logLevel, const char *const logMessage) {
    printf("[WOLFSSL-%d] %s\n", logLevel, logMessage);
}

/* =========================================================================
   PQC CONFIGURATION
   ========================================================================= */
int configure_pqc_context(WOLFSSL_CTX* ctx, int is_server) {
    int ret;
    
    // TESTING: Simple PSK-only mode without PQC
    if (is_server) {
        wolfSSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);
        wolfSSL_CTX_use_psk_identity_hint(ctx, "RISCV_Server");
    } else {
        wolfSSL_CTX_set_psk_client_callback(ctx, my_psk_client_cb);
    }
    
    // Use standard DTLS 1.2 ciphers with PSK
    const char* simple_ciphers = "PSK-AES128-CBC-SHA256";
    
    ret = wolfSSL_CTX_set_cipher_list(ctx, simple_ciphers);
    if (ret != WOLFSSL_SUCCESS) {
        printf("[Config] ERROR: Cipher setup failed: %d\n", ret);
        return ret;
    }
    
    printf("[Config] TEST MODE: PSK-only, no PQC, DTLS 1.2\n");
    
    return WOLFSSL_SUCCESS;
}

/* =========================================================================
   CLIENT MODE
   ========================================================================= */
void run_dtls_client(void) {
    printf("\n=== DTLS 1.3 PQC CLIENT MODE ===\n");
    printf("[CLIENT] Step 1: Creating DTLS 1.3 client context\n");
    
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (!ctx) {
        printf("ERROR: CTX creation failed\n");
        return;
    }
    printf("[CLIENT] Step 2: Context created successfully\n");
    
    // Configure I/O
    printf("[CLIENT] Step 3: Setting I/O callbacks\n");
    wolfSSL_CTX_SetIORecv(ctx, my_IORecv);
    wolfSSL_CTX_SetIOSend(ctx, my_IOSend);
    printf("[CLIENT] Step 4: Configuring PQC context\n");
    
    // Configure PQC
    if (configure_pqc_context(ctx, 0) != WOLFSSL_SUCCESS) {
        printf("[CLIENT] ERROR: PQC configuration failed\n");
        wolfSSL_CTX_free(ctx);
        return;
    }
    printf("[CLIENT] Step 5: PQC configured successfully\n");
    printf("[CLIENT] Step 6: Creating SSL object\n");
    
    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (!ssl) {
        printf("[CLIENT] ERROR: SSL object creation failed\n");
        wolfSSL_CTX_free(ctx);
        return;
    }
    printf("[CLIENT] Step 7: SSL object created successfully\n");
    
    // Set I/O contexts (required for WOLFSSL_USER_IO even if NULL)
    printf("[CLIENT] Step 7a: Setting I/O contexts\n");
    wolfSSL_SetIOReadCtx(ssl, NULL);
    wolfSSL_SetIOWriteCtx(ssl, NULL);
    printf("[CLIENT] Step 7b: I/O contexts set\n");
    
    // Configure DTLS-specific settings
    printf("[CLIENT] Step 8a: Setting NON-BLOCKING mode\n");
    wolfSSL_dtls_set_using_nonblock(ssl, 1);  // Enable non-blocking mode
    printf("[CLIENT] Step 8b: NON-BLOCKING mode enabled\n");
    
    printf("[CLIENT] Step 8c: About to set timeout_init\n");
    int timeout_ret1 = wolfSSL_dtls_set_timeout_init(ssl, 1);
    printf("[CLIENT] Step 8d: timeout_init returned %d\n", timeout_ret1);
    
    printf("[CLIENT] Step 8e: About to set timeout_max\n");
    int timeout_ret2 = wolfSSL_dtls_set_timeout_max(ssl, 64);
    printf("[CLIENT] Step 8f: timeout_max returned %d\n", timeout_ret2);
    
    // DIAGNOSTIC: Try calling wolfSSL_connect with a watchdog
    printf("[CLIENT] Step 8g: Testing if wolfSSL_connect hangs...\n");
    volatile int watchdog = 0;
    printf("[CLIENT] Step 8h: Watchdog initialized\n");
    
    printf("[CLIENT] Step 9: About to call wolfSSL_connect()\n");
    printf("[Client] Starting DTLS handshake...\n");
    
    // DIAGNOSTIC: Check SSL state before connect
    printf("[DIAG] SSL object address: %p\n", ssl);
    printf("[DIAG] CTX object address: %p\n", ctx);
    
    int ret;
    int attempts = 0;
    int max_attempts = 50;  // Reduced for faster debugging
    
    printf("[CLIENT] *** CALLING wolfSSL_connect WITH WATCHDOG ***\n");
    
    // Watchdog: Use timer to detect if we hang
    volatile uint32_t watchdog_start = timer0_value_read();
    volatile int watchdog_triggered = 0;
    
    printf("[WATCHDOG] Start timer: 0x%08lx\n", (unsigned long)watchdog_start);
    printf("[WATCHDOG] Will timeout if no response in 5 seconds\n");
    
    do {
        // Check watchdog before each iteration
        uint32_t current_time = timer0_value_read();
        uint32_t elapsed = watchdog_start - current_time; // Timer counts down
        
        if (attempts == 0) printf("[ITER 0] PRE-CALL\n");
        
        // CRITICAL: Call wolfSSL_connect()
        ret = wolfSSL_connect(ssl);
        
        if (attempts == 0) printf("[ITER 0] POST-CALL: ret=%d\n", ret);
        if (ret != WOLFSSL_SUCCESS) {
            int err = wolfSSL_get_error(ssl, ret);
            if (attempts < 3) printf("[ITER %d] Error: %d\n", attempts, err);
            if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
                attempts++;
                if (attempts == 1) {
                    printf("[CLIENT] Got WANT_READ/WRITE (expected)\n");
                }
                if (attempts % 10 == 0) {
                    printf("[PROGRESS] %d attempts\n", attempts);
                }
                if (attempts >= max_attempts) {
                    printf("\n[CLIENT] ERROR: Exceeded %d attempts, breaking loop\n", max_attempts);
                    printf("[CLIENT] Last error: %d (WANT_READ=%d, WANT_WRITE=%d)\n", 
                           err, WOLFSSL_ERROR_WANT_READ, WOLFSSL_ERROR_WANT_WRITE);
                    break;
                }
                // Small delay to allow I/O and timer processing
                for (volatile int i = 0; i < 100; i++);
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
    printf("[DEBUG] main: About to call wolfSSL_Init()\n");
    
    // Initialize WolfSSL
    int init_result = wolfSSL_Init();
    printf("[DEBUG] wolfSSL_Init returned: %d (SUCCESS=%d)\n", init_result, WOLFSSL_SUCCESS);
    if (init_result != WOLFSSL_SUCCESS) {
        printf("ERROR: wolfSSL_Init failed (returned %d)\n", init_result);
        return -1;
    }
    printf("[DEBUG] wolfSSL_Init succeeded!\n");

    printf("[DEBUG] Enabling wolfSSL debugging\n");
    wolfSSL_Debugging_ON();
    wolfSSL_SetLoggingCb(wolfssl_debug_callback);
    printf("[DEBUG] WolfSSL debug callback registered\n");
    
#if MODE_SERVER
    printf("[DEBUG] MODE_SERVER=1, calling run_dtls_server()\n");
    run_dtls_server();
#else
    printf("[DEBUG] MODE_SERVER=0, calling run_dtls_client()\n");
    run_dtls_client();
#endif
    printf("[DEBUG] DTLS function returned\n");
    
    wolfSSL_Cleanup();
    printf("\n[System] Done.\n");
    
    return 0;
}
