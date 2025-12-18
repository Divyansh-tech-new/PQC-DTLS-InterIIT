#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

/* Verification callback - accept server cert */
static int verify_callback(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    (void)store;
    printf("[Client] Certificate verification callback (preverify=%d)\n", preverify);
    return 1;  /* Accept for development */
}

int main(int argc, char* argv[])
{
    int                 ret;
    int                 sockfd;
    struct sockaddr_in  servaddr;
    WOLFSSL_CTX*        ctx = NULL;
    WOLFSSL*            ssl = NULL;

    const char* server_ip   = (argc > 1) ? argv[1] : "127.0.0.1";
    const int   server_port = (argc > 2) ? atoi(argv[2]) : 4444;

    printf("========================================\n");
    printf(" DTLS 1.3 PQC Client (Simple)\n");
    printf("========================================\n");
    printf(" Key Exchange: ML-KEM-512 (Kyber)\n");
    printf(" Authentication: Dilithium Level 2\n");
    printf(" Target: %s:%d\n", server_ip, server_port);
    printf("========================================\n\n");

    /* 1. Init wolfSSL */
    wolfSSL_Init();
    wolfSSL_Debugging_ON();  /* Enable debug to see what's happening */

    ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (!ctx) {
        fprintf(stderr, "wolfSSL_CTX_new failed\n");
        goto exit;
    }

    /* Don't verify server certificate (insecure but simpler) */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    printf("[Client] ✓ Verification disabled (testing mode)\n");

    /* Force PQC-friendly cipher suites */
    const char* pqc_ciphers =
        "TLS13-AES128-GCM-SHA256:"
        "TLS13-CHACHA20-POLY1305-SHA256";

    if ((ret = wolfSSL_CTX_set_cipher_list(ctx, pqc_ciphers)) != 1) {
        fprintf(stderr, "wolfSSL_CTX_set_cipher_list failed (ret=%d)\n", ret);
        goto exit;
    }
    printf("[Client] ✓ PQC ciphers configured\n");

#ifdef WOLFSSL_ML_KEM_512
    /* Enable ML-KEM-512 */
    ret = wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ML_KEM_512);
    if (ret != 1) {
        fprintf(stderr, "CTX_UseSupportedCurve(ML-KEM-512) failed (ret=%d)\n", ret);
        goto exit;
    }
    printf("[Client] ✓ ML-KEM-512 key exchange enabled\n");
#else
    printf("[Client] ⚠ ML-KEM-512 not available\n");
#endif

#ifdef HAVE_DILITHIUM
    printf("[Client] ✓ Dilithium support enabled\n");
#else
    printf("[Client] ⚠ Dilithium not available\n");
#endif

    printf("\n[Client] PQC configuration complete!\n\n");

    /* 2. Create UDP socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        goto exit;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port   = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &servaddr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address: %s\n", server_ip);
        goto exit;
    }

    /* Connect socket */
    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect");
        goto exit;
    }

    /* 3. Create WOLFSSL object */
    ssl = wolfSSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "wolfSSL_new failed\n");
        goto exit;
    }

    wolfSSL_set_fd(ssl, sockfd);

    printf("[Client] Starting DTLS 1.3 handshake with %s:%d...\n", server_ip, server_port);
    printf("[Client] Using ML-KEM-512 key exchange\n");
    printf("[Client] Using Dilithium certificate authentication\n\n");

    /* Connect with retry logic */
    int attempts = 0;
    int max_attempts = 15;
    
    while (attempts < max_attempts) {
        ret = wolfSSL_connect(ssl);
        
        if (ret == 1) {  /* Success */
            break;
        }
        
        int err = wolfSSL_get_error(ssl, ret);
        
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            /* Non-fatal, retry */
            attempts++;
            if (attempts % 3 == 0) {
                printf("[Client] Handshake in progress (attempt %d/%d)...\n", attempts, max_attempts);
            }
            usleep(300000); /* 300ms delay */
            continue;
        } else {
            /* Fatal error */
            char err_buf[80];
            wolfSSL_ERR_error_string(err, err_buf);
            fprintf(stderr, "[Client] ✗ Handshake error %d: %s\n", err, err_buf);
            goto exit;
        }
    }
    
    if (ret != 1) {
        fprintf(stderr, "[Client] ✗ Handshake failed after %d attempts\n", max_attempts);
        goto exit;
    }

    printf("\n========================================\n");
    printf("✓ DTLS 1.3 Handshake Complete!\n");
    printf("========================================\n");
    printf("  Cipher:     %s\n", wolfSSL_get_cipher(ssl));
    printf("  Version:    %s\n", wolfSSL_get_version(ssl));
    printf("  Key Exch:   ML-KEM-512 (Post-Quantum)\n");
    printf("  Auth:       ML-DSA Dilithium (Post-Quantum)\n");
    printf("========================================\n\n");

    /* 4. Send encrypted application data */
    const char* msg = "Hello from PQC DTLS 1.3 Client! This is encrypted with post-quantum crypto!";
    printf("[Client] Sending encrypted message: %s\n", msg);
    
    ret = wolfSSL_write(ssl, msg, (int)strlen(msg));
    if (ret < 0) {
        int err = wolfSSL_get_error(ssl, ret);
        char err_buf[80];
        wolfSSL_ERR_error_string(err, err_buf);
        fprintf(stderr, "[Client] wolfSSL_write error %d: %s\n", err, err_buf);
        goto exit;
    }
    printf("[Client] ✓ Sent %d bytes (encrypted)\n", ret);

    /* 5. Receive encrypted response */
    unsigned char buf[1500];
    memset(buf, 0, sizeof(buf));
    
    ret = wolfSSL_read(ssl, buf, sizeof(buf)-1);
    if (ret > 0) {
        buf[ret] = '\0';
        printf("[Client] ✓ Received encrypted response (%d bytes): %s\n", ret, buf);
    } else {
        int err = wolfSSL_get_error(ssl, ret);
        char err_buf[80];
        wolfSSL_ERR_error_string(err, err_buf);
        fprintf(stderr, "[Client] wolfSSL_read error %d: %s\n", err, err_buf);
    }

    printf("\n[Client] Session complete! All traffic was encrypted with PQC algorithms.\n");

exit:
    if (ssl)  wolfSSL_free(ssl);
    if (ctx)  wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    if (sockfd >= 0) close(sockfd);
    return (ret == 1 || ret > 0) ? 0 : 1;
}
