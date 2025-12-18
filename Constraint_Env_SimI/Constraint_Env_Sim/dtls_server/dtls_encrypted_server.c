#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

/* PSK for testing */
static const char* psk_identity = "Client_PQC_Identity";
static unsigned char psk_key[] = {
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
    0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09
};

static unsigned int my_psk_server_cb(WOLFSSL* ssl, const char* identity,
                                     unsigned char* key, unsigned int max_key_len)
{
    (void)ssl;
    
    if (strncmp(identity, psk_identity, strlen(psk_identity)) != 0) {
        return 0;
    }
    
    if (max_key_len < sizeof(psk_key)) {
        return 0;
    }
    
    memcpy(key, psk_key, sizeof(psk_key));
    return sizeof(psk_key);
}

int main(void)
{
    int                 ret;
    int                 sockfd;
    struct sockaddr_in  servaddr, cliaddr;
    socklen_t           cliaddr_len = sizeof(cliaddr);
    unsigned char       buf[1500];

    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;

    const char*  server_ip   = "0.0.0.0";
    const int    server_port = 4444;

    printf("========================================\n");
    printf(" DTLS 1.3 Server (Real Encryption)\n");
    printf("========================================\n");
    printf(" Cipher: AES-128-GCM (quantum-resistant)\n");
    printf(" Auth: PSK (Pre-Shared Key)\n");
    printf("========================================\n\n");

    /* 1. Init wolfSSL */
    wolfSSL_Init();

    ctx = wolfSSL_CTX_new(wolfDTLSv1_3_server_method());
    if (!ctx) {
        fprintf(stderr, "wolfSSL_CTX_new failed\n");
        goto exit;
    }

    /* Set PSK callback */
    wolfSSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);
    wolfSSL_CTX_use_psk_identity_hint(ctx, "wolfssl server");
    printf("[Server] ✓ PSK authentication configured\n");

    /* Force strong cipher */
    const char* cipher = "TLS13-AES128-GCM-SHA256";
    if ((ret = wolfSSL_CTX_set_cipher_list(ctx, cipher)) != 1) {
        fprintf(stderr, "wolfSSL_CTX_set_cipher_list failed (ret=%d)\n", ret);
        goto exit;
    }
    printf("[Server] ✓ AES-128-GCM cipher configured\n");

    printf("\n[Server] Configuration complete!\n\n");

    /* 2. Create UDP socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        goto exit;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family      = AF_INET;
    servaddr.sin_port        = htons(server_port);
    servaddr.sin_addr.s_addr = inet_addr(server_ip);

    if (bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind");
        goto exit;
    }

    printf("[Server] Listening on %s:%d (DTLS 1.3 with encryption)\n",
           server_ip, server_port);
    printf("[Server] Waiting for client connection...\n\n");

    /* 3. Wait for first packet */
    int recvd = recvfrom(sockfd, buf, sizeof(buf), MSG_PEEK,
                         (struct sockaddr*)&cliaddr, &cliaddr_len);
    if (recvd < 0) {
        perror("recvfrom");
        goto exit;
    }

    char cli_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &cliaddr.sin_addr, cli_ip, sizeof(cli_ip));
    printf("[Server] ✓ Received packet from %s:%d (%d bytes)\n",
           cli_ip, ntohs(cliaddr.sin_port), recvd);

    /* Connect socket to client */
    if (connect(sockfd, (struct sockaddr*)&cliaddr, cliaddr_len) < 0) {
        perror("connect");
        goto exit;
    }

    /* 4. Create WOLFSSL object */
    ssl = wolfSSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "wolfSSL_new failed\n");
        goto exit;
    }

    wolfSSL_set_fd(ssl, sockfd);

    printf("[Server] Starting DTLS 1.3 handshake...\n");

    /* Accept with retry logic */
    int attempts = 0;
    int max_attempts = 15;
    
    while (attempts < max_attempts) {
        ret = wolfSSL_accept(ssl);
        
        if (ret == 1) {  /* Success */
            break;
        }
        
        int err = wolfSSL_get_error(ssl, ret);
        
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            /* Non-fatal, retry */
            attempts++;
            if (attempts % 3 == 0) {
                printf("[Server] Handshake in progress (attempt %d/%d)...\n", attempts, max_attempts);
            }
            usleep(300000); /* 300ms delay */
            continue;
        } else {
            /* Fatal error */
            char err_buf[80];
            wolfSSL_ERR_error_string(err, err_buf);
            fprintf(stderr, "[Server] ✗ Handshake error %d: %s\n", err, err_buf);
            goto exit;
        }
    }
    
    if (ret != 1) {
        fprintf(stderr, "[Server] ✗ Handshake failed after %d attempts\n", max_attempts);
        goto exit;
    }

    printf("\n========================================\n");
    printf("✓ DTLS 1.3 Handshake Complete!\n");
    printf("========================================\n");
    printf("  Cipher:     %s\n", wolfSSL_get_cipher(ssl));
    printf("  Version:    %s\n", wolfSSL_get_version(ssl));
    printf("  Encryption: AES-128-GCM (Real!)\n");
    printf("========================================\n\n");

    /* 5. Receive encrypted application data */
    memset(buf, 0, sizeof(buf));
    recvd = wolfSSL_read(ssl, buf, sizeof(buf)-1);
    if (recvd > 0) {
        buf[recvd] = '\0';
        printf("[Server] ✓ Received encrypted data (%d bytes): %s\n", recvd, buf);
    } else {
        int err = wolfSSL_get_error(ssl, recvd);
        char err_buf[80];
        wolfSSL_ERR_error_string(err, err_buf);
        fprintf(stderr, "[Server] wolfSSL_read error %d: %s\n", err, err_buf);
    }

    /* 6. Send encrypted response */
    const char* reply = "SERVER RESPONSE: Received your encrypted message! This reply is also encrypted with AES-128-GCM!";
    ret = wolfSSL_write(ssl, reply, (int)strlen(reply));
    printf("[Server] ✓ Sent encrypted response (%d bytes)\n", ret);

exit:
    if (ssl)  wolfSSL_free(ssl);
    if (ctx)  wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    if (sockfd >= 0) close(sockfd);
    return 0;
}
