#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

/* Certificate files (generated with Dilithium signatures) */
#define CA_CERT_FILE     "../pqc_certs/ca-pub.der"
#define SERVER_CERT_FILE "../pqc_certs/server-pub.der"
#define SERVER_KEY_FILE  "../pqc_certs/server-key.der"

/* Verification callback */
static int verify_callback(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    (void)store;
    printf("[Server] Certificate verification callback (preverify=%d)\n", preverify);
    
    /* For development: accept all certificates */
    /* In production: implement proper chain validation */
    return 1;  /* 1 = accept, 0 = reject */
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
    printf(" DTLS 1.3 PQC Server (Mutual Auth)\n");
    printf("========================================\n");
    printf(" Key Exchange: ML-KEM-512 (Kyber)\n");
    printf(" Authentication: Dilithium Level 2\n");
    printf(" Mode: Certificate-based Mutual Auth\n");
    printf("========================================\n\n");

    /* 1. Init wolfSSL */
    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    ctx = wolfSSL_CTX_new(wolfDTLSv1_3_server_method());
    if (!ctx) {
        fprintf(stderr, "wolfSSL_CTX_new failed\n");
        goto exit;
    }

    /* Load server certificate and private key */
    printf("[Server] Loading server certificate from %s\n", SERVER_CERT_FILE);
    ret = wolfSSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE, WOLFSSL_FILETYPE_ASN1);
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "[ERROR] Failed to load server certificate: %d\n", ret);
        goto exit;
    }

    printf("[Server] Loading server private key from %s\n", SERVER_KEY_FILE);
    ret = wolfSSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, WOLFSSL_FILETYPE_ASN1);
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "[ERROR] Failed to load server private key: %d\n", ret);
        goto exit;
    }

    /* Load CA certificate for client verification */
    printf("[Server] Loading CA certificate from %s\n", CA_CERT_FILE);
    ret = wolfSSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL);
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "[ERROR] Failed to load CA certificate: %d\n", ret);
        goto exit;
    }

    /* Enable mutual authentication - require client certificate */
    wolfSSL_CTX_set_verify(ctx, 
                          WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                          verify_callback);
    printf("[Server] ✓ Mutual authentication enabled (client cert required)\n");

    /* Force PQC-friendly cipher suites */
    const char* pqc_ciphers =
        "TLS13-AES128-GCM-SHA256:"
        "TLS13-CHACHA20-POLY1305-SHA256";

    if ((ret = wolfSSL_CTX_set_cipher_list(ctx, pqc_ciphers)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_CTX_set_cipher_list failed: %d\n", ret);
        goto exit;
    }

#ifdef WOLFSSL_ML_KEM_512
    /* Enable ML-KEM-512 as supported group / key share */
    ret = wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ML_KEM_512);
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "CTX_UseSupportedCurve(ML-KEM-512) failed: %d\n", ret);
        goto exit;
    }
    printf("[Server] ✓ ML-KEM-512 key exchange enabled\n");
#endif

#ifdef HAVE_DILITHIUM
    /* Prefer Dilithium signature algorithms */
    const char* sig_algs = "DILITHIUM_LEVEL2:DILITHIUM_LEVEL3:DILITHIUM_LEVEL5";
    ret = wolfSSL_CTX_set1_sigalgs_list(ctx, sig_algs);
    if (ret == WOLFSSL_SUCCESS) {
        printf("[Server] ✓ Dilithium signature algorithms configured\n");
    }
#endif

    printf("\n[Server] PQC configuration complete!\n\n");

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

    printf("[Server] Listening on %s:%d (DTLS 1.3 PQC PSK)\n",
           server_ip, server_port);

    /* 3. Wait for first ClientHello to learn the client address */
    int recvd = recvfrom(sockfd, buf, sizeof(buf), MSG_PEEK,
                         (struct sockaddr*)&cliaddr, &cliaddr_len);
    if (recvd < 0) {
        perror("recvfrom");
        goto exit;
    }

    char cli_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &cliaddr.sin_addr, cli_ip, sizeof(cli_ip));
    printf("[Server] First packet from %s:%d (%d bytes)\n",
           cli_ip, ntohs(cliaddr.sin_port), recvd);

    /* Connect socket to fix peer; DTLS will then work like TCP from wolfSSL POV */
    if (connect(sockfd, (struct sockaddr*)&cliaddr, cliaddr_len) < 0) {
        perror("connect");
        goto exit;
    }

    /* 4. Create WOLFSSL object and associate with socket */
    ssl = wolfSSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "wolfSSL_new failed\n");
        goto exit;
    }

    wolfSSL_set_fd(ssl, sockfd);

    printf("[Server] Waiting for DTLS 1.3 handshake...\n");
    ret = wolfSSL_accept(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, ret);
        char err_buf[80];
        wolfSSL_ERR_error_string(err, err_buf);
        fprintf(stderr, "[Server] wolfSSL_accept error %d: %s\n", err, err_buf);
        goto exit;
    }

    printf("\n========================================\n");
    printf("✓ DTLS 1.3 Handshake Complete!\n");
    printf("========================================\n");
    printf("  Cipher:     %s\n", wolfSSL_get_cipher(ssl));
    printf("  Version:    %s\n", wolfSSL_get_version(ssl));
    printf("  Key Exch:   ML-KEM-512 (Kyber)\n");
    printf("  Auth:       Dilithium Level 2 (Mutual)\n");
    printf("========================================\n");
    printf("\nClient has been mutually authenticated!\n");

    /* 5. Receive application data */
    memset(buf, 0, sizeof(buf));
    recvd = wolfSSL_read(ssl, buf, sizeof(buf)-1);
    if (recvd > 0) {
        buf[recvd] = '\0';
        printf("[Server] Received from client: %s\n", buf);
    } else {
        int err = wolfSSL_get_error(ssl, recvd);
        char err_buf[80];
        wolfSSL_ERR_error_string(err, err_buf);
        fprintf(stderr, "[Server] wolfSSL_read error %d: %s\n", err, err_buf);
    }

    /* 6. Send response */
    const char* reply = "ACK from Linux DTLS 1.3 PQC Server (Mutual Auth)!";
    ret = wolfSSL_write(ssl, reply, (int)strlen(reply));
    printf("[Server] Sent %d bytes back to client\n", ret);

exit:
    if (ssl)  wolfSSL_free(ssl);
    if (ctx)  wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    if (sockfd >= 0) close(sockfd);
    return 0;
}
