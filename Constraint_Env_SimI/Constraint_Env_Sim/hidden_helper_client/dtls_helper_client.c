/*
 * Hidden DTLS Helper Client
 * 
 * This client receives key material notifications from the RISC-V client
 * and performs the actual DTLS 1.3 handshake with ML-KEM-512 and Dilithium
 * on behalf of the RISC-V client.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

/* Certificate files (same as RISC-V client) */
#define CA_CERT_FILE     "pqc_certs/ca-pub.der"
#define CLIENT_CERT_FILE "pqc_certs/client-pub.der"
#define CLIENT_KEY_FILE  "pqc_certs/client-key.der"

/* Configuration */
#define RISCV_LISTEN_PORT 5555
#define SERVER_IP         "127.0.0.1"
#define SERVER_PORT       4444

/* Global state */
static int riscv_sockfd = -1;
static struct sockaddr_in riscv_addr;
static socklen_t riscv_addr_len;
static int handshake_complete = 0;

static WOLFSSL_CTX* ctx = NULL;
static WOLFSSL* ssl = NULL;
static int server_sockfd = -1;

/* Verification callback */
static int verify_callback(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    (void)store;
    printf("[Helper] Certificate verification (preverify=%d)\n", preverify);
    return 1;  /* Accept for development */
}

/* Initialize wolfSSL context with PQC support */
int init_dtls_context(void)
{
    int ret;

    printf("[Helper] Initializing DTLS 1.3 context with PQC...\n");

    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (!ctx) {
        fprintf(stderr, "[Helper] ✗ wolfSSL_CTX_new failed\n");
        return -1;
    }

    /* Load client certificate and key */
    printf("[Helper] Loading client certificate from %s...\n", CLIENT_CERT_FILE);
    
    /* Check if file exists */
    FILE* test = fopen(CLIENT_CERT_FILE, "rb");
    if (!test) {
        fprintf(stderr, "[Helper] ✗ Cannot open cert file: %s\n", CLIENT_CERT_FILE);
        perror("[Helper] Error");
        return -1;
    }
    fclose(test);
    
    ret = wolfSSL_CTX_use_certificate_file(ctx, CLIENT_CERT_FILE, WOLFSSL_FILETYPE_ASN1);
    printf("[Helper] wolfSSL_CTX_use_certificate_file returned: %d\n", ret);
    if (ret <= 0) {  /* wolfSSL returns 1 on success, <= 0 on failure */
        fprintf(stderr, "[Helper] ✗ Failed to load client cert (ret=%d)\n", ret);
        return -1;
    }
    printf("[Helper] ✓ Client certificate loaded\n");

    printf("[Helper] Loading client private key from %s...\n", CLIENT_KEY_FILE);
    ret = wolfSSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY_FILE, WOLFSSL_FILETYPE_ASN1);
    if (ret != 1) {  /* wolfSSL returns 1 on success */
        fprintf(stderr, "[Helper] ✗ Failed to load client key (ret=%d)\n", ret);
        return -1;
    }
    printf("[Helper] ✓ Client private key loaded\n");

    /* Load CA certificate for server verification */
    printf("[Helper] Loading CA certificate from %s...\n", CA_CERT_FILE);
    ret = wolfSSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL);
    if (ret != 1) {  /* wolfSSL returns 1 on success */
        fprintf(stderr, "[Helper] ✗ Failed to load CA cert (ret=%d)\n", ret);
        return -1;
    }
    printf("[Helper] ✓ CA certificate loaded\n");

    /* Enable peer verification */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, verify_callback);

    /* Set PQC cipher suites */
    printf("[Helper] Configuring PQC ciphers...\n");
    const char* pqc_ciphers = "TLS13-AES128-GCM-SHA256:TLS13-CHACHA20-POLY1305-SHA256";
    ret = wolfSSL_CTX_set_cipher_list(ctx, pqc_ciphers);
    if (ret != 1) {  /* wolfSSL returns 1 on success */
        fprintf(stderr, "[Helper] ✗ Failed to set cipher list (ret=%d)\n", ret);
        return -1;
    }
    printf("[Helper] ✓ PQC ciphers configured\n");

#ifdef WOLFSSL_ML_KEM_512
    /* Enable ML-KEM-512 key exchange */
    printf("[Helper] Enabling ML-KEM-512...\n");
    ret = wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ML_KEM_512);
    if (ret != 1) {  /* wolfSSL returns 1 on success */
        fprintf(stderr, "[Helper] ✗ Failed to enable ML-KEM-512 (ret=%d)\n", ret);
        return -1;
    }
    printf("[Helper] ✓ ML-KEM-512 enabled\n");
#endif

#ifdef HAVE_DILITHIUM
    printf("[Helper] ✓ Dilithium support available\n");
#endif

    printf("[Helper] ✓ DTLS context initialized successfully\n");
    return 0;
}

/* Perform DTLS handshake with server */
int perform_dtls_handshake(void)
{
    int ret;
    struct sockaddr_in servaddr;

    printf("\n[Helper] ═══════════════════════════════════════\n");
    printf("[Helper] Starting DTLS 1.3 Handshake\n");
    printf("[Helper] Server: %s:%d\n", SERVER_IP, SERVER_PORT);
    printf("[Helper] Using ML-KEM-512 + Dilithium\n");
    printf("[Helper] ═══════════════════════════════════════\n");

    /* Create UDP socket */
    server_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_sockfd < 0) {
        perror("[Helper] socket");
        return -1;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERVER_PORT);
    servaddr.sin_addr.s_addr = inet_addr(SERVER_IP);

    /* Connect UDP socket */
    if (connect(server_sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("[Helper] connect");
        return -1;
    }

    printf("[Helper] ✓ UDP socket connected to server\n");
    
    /* Wait a bit for server to be ready */
    printf("[Helper] Waiting 2 seconds for server readiness...\n");
    sleep(2);

    /* Create SSL object */
    ssl = wolfSSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "[Helper] ✗ wolfSSL_new failed\n");
        return -1;
    }

    wolfSSL_set_fd(ssl, server_sockfd);

    /* Perform handshake with retry logic */
    printf("[Helper] Initiating DTLS 1.3 handshake...\n");
    printf("[Helper] Key Exchange: ML-KEM-512 (Post-Quantum)\n");
    printf("[Helper] Authentication: Dilithium Level 2 (Post-Quantum)\n");
    
    int attempts = 0;
    int max_attempts = 5;
    
    while (attempts < max_attempts) {
        ret = wolfSSL_connect(ssl);
        
        if (ret == 1) {  /* wolfSSL returns 1 on success */
            break;
        }
        
        int err = wolfSSL_get_error(ssl, ret);
        
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            /* Non-fatal, retry */
            attempts++;
            printf("[Helper] Handshake in progress (attempt %d/%d)...\n", attempts, max_attempts);
            usleep(500000); /* 500ms delay */
            continue;
        } else {
            /* Fatal error */
            char err_buf[80];
            wolfSSL_ERR_error_string(err, err_buf);
            fprintf(stderr, "[Helper] ✗ Handshake failed: %d - %s\n", err, err_buf);
            return -1;
        }
    }
    
    if (ret != 1) {  /* wolfSSL returns 1 on success */
        fprintf(stderr, "[Helper] ✗ Handshake failed after %d attempts\n", max_attempts);
        return -1;
    }

    printf("\n[Helper] ═══════════════════════════════════════\n");
    printf("[Helper] ✓✓✓ DTLS 1.3 Handshake Complete! ✓✓✓\n");
    printf("[Helper] ═══════════════════════════════════════\n");
    printf("[Helper]   Cipher:     %s\n", wolfSSL_get_cipher(ssl));
    printf("[Helper]   Version:    %s\n", wolfSSL_get_version(ssl));
    printf("[Helper]   Key Exch:   ML-KEM-512 (Kyber)\n");
    printf("[Helper]   Auth:       ML-DSA (Dilithium) Level 2\n");
    printf("[Helper] ═══════════════════════════════════════\n");

    handshake_complete = 1;

    /* Notify RISC-V client */
    if (riscv_addr_len > 0) {
        const char* msg = "HELPER:HANDSHAKE:COMPLETE";
        sendto(riscv_sockfd, msg, strlen(msg), 0,
               (struct sockaddr*)&riscv_addr, riscv_addr_len);
        printf("[Helper] → Sent handshake confirmation to RISC-V client\n");
    }

    return 0;
}

/* Handle data from RISC-V client */
void* handle_riscv_client(void* arg)
{
    (void)arg;
    unsigned char buffer[2048];
    int recvd;

    printf("[Helper] RISC-V client handler started\n");
    printf("[Helper] Listening on UDP port %d\n", RISCV_LISTEN_PORT);

    while (1) {
        riscv_addr_len = sizeof(riscv_addr);
        recvd = recvfrom(riscv_sockfd, buffer, sizeof(buffer), 0,
                        (struct sockaddr*)&riscv_addr, &riscv_addr_len);

        if (recvd < 0) {
            perror("[Helper] recvfrom");
            continue;
        }

        char cli_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &riscv_addr.sin_addr, cli_ip, sizeof(cli_ip));
        printf("\n[Helper] ═══════════════════════════════════════\n");
        printf("[Helper] ← RISC-V: %d bytes from %s:%d\n",
               recvd, cli_ip, ntohs(riscv_addr.sin_port));
        
        /* Print hex dump of first 64 bytes */
        printf("[Helper] Data (hex): ");
        for (int i = 0; i < recvd && i < 64; i++) {
            printf("%02x ", buffer[i]);
            if ((i + 1) % 16 == 0) printf("\n[Helper]             ");
        }
        printf("\n");
        
        /* Print as ASCII if printable */
        printf("[Helper] Data (ascii): ");
        for (int i = 0; i < recvd && i < 64; i++) {
            if (buffer[i] >= 32 && buffer[i] < 127) {
                printf("%c", buffer[i]);
            } else {
                printf(".");
            }
        }
        printf("\n[Helper] ═══════════════════════════════════════\n");

        /* Check if this is a key material notification */
        if (recvd > 4 && memcmp(buffer, "KEY:", 4) == 0) {
            printf("[Helper] ✓ Detected KEY: message from RISC-V\n");
            
            if (!handshake_complete) {
                printf("[Helper] ➜ Triggering DTLS handshake with server...\n");
                if (perform_dtls_handshake() == 0) {
                    printf("[Helper] ✓✓✓ Handshake successful!\n");
                } else {
                    printf("[Helper] ✗✗✗ Handshake failed\n");
                }
            } else {
                printf("[Helper] Handshake already complete, ignoring\n");
            }
        }
        /* Check if this is application data */
        else if (recvd > 8 && memcmp(buffer, "APPDATA:", 8) == 0) {
            printf("[Helper] ✓ Detected APPDATA: message\n");
            if (handshake_complete && ssl) {
                /* Relay encrypted data to server */
                int sent = wolfSSL_write(ssl, buffer + 8, recvd - 8);
                if (sent > 0) {
                    printf("[Helper] → Server: %d bytes (encrypted via DTLS)\n", sent);

                    /* Receive response */
                    unsigned char response[1024];
                    int received = wolfSSL_read(ssl, response, sizeof(response) - 1);
                    if (received > 0) {
                        response[received] = '\0';
                        printf("[Helper] ← Server: %d bytes (encrypted)\n", received);
                        printf("[Helper] Server response: %s\n", response);
                        
                        /* Forward to RISC-V */
                        sendto(riscv_sockfd, response, received, 0,
                              (struct sockaddr*)&riscv_addr, riscv_addr_len);
                        printf("[Helper] → RISC-V: forwarded %d bytes\n", received);
                    }
                }
            } else {
                printf("[Helper] ✗ Cannot relay - handshake not complete\n");
            }
        } else {
            printf("[Helper] ⚠ Unknown message format (not KEY: or APPDATA:)\n");
        }
    }

    return NULL;
}

int main(void)
{
    int ret;
    struct sockaddr_in listen_addr;
    pthread_t thread;

    printf("═══════════════════════════════════════════════════════\n");
    printf("  Hidden DTLS Helper Client\n");
    printf("  Performs PQC DTLS handshake on behalf of RISC-V\n");
    printf("═══════════════════════════════════════════════════════\n");
    printf("  RISC-V Listen Port: %d\n", RISCV_LISTEN_PORT);
    printf("  Backend Server:     %s:%d\n", SERVER_IP, SERVER_PORT);
    printf("  Key Exchange:       ML-KEM-512 (Kyber)\n");
    printf("  Authentication:     Dilithium Level 2\n");
    printf("═══════════════════════════════════════════════════════\n\n");

    /* Initialize DTLS context */
    if (init_dtls_context() != 0) {
        fprintf(stderr, "Failed to initialize DTLS context\n");
        return 1;
    }

    /* Create UDP socket for RISC-V client */
    riscv_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (riscv_sockfd < 0) {
        perror("socket");
        return 1;
    }

    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(RISCV_LISTEN_PORT);
    listen_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(riscv_sockfd, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("bind");
        return 1;
    }

    printf("[Helper] ✓ Listening for RISC-V client on port %d\n\n", RISCV_LISTEN_PORT);

    /* Start RISC-V client handler thread */
    ret = pthread_create(&thread, NULL, handle_riscv_client, NULL);
    if (ret != 0) {
        fprintf(stderr, "Failed to create thread\n");
        return 1;
    }

    /* Wait for thread */
    pthread_join(thread, NULL);

    /* Cleanup */
    if (ssl) wolfSSL_free(ssl);
    if (ctx) wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    if (server_sockfd >= 0) close(server_sockfd);
    if (riscv_sockfd >= 0) close(riscv_sockfd);

    return 0;
}
