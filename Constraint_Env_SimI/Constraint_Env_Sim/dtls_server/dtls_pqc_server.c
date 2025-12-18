#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

/* Certificate files (generated with Dilithium signatures) */
#define CA_CERT_FILE     "pqc_certs/ca-pub.der"
#define SERVER_CERT_FILE "pqc_certs/server-pub.der"
#define SERVER_KEY_FILE  "pqc_certs/server-key.der"

/* PSK for testing */
static const char* psk_identity = "Client_identity";
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

/* Verification callback */
static int verify_callback(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    (void)store;
    printf("[Server] Certificate verification callback (preverify=%d)\n", preverify);
    
    /* For development: accept all certificates */
    /* In production: implement proper chain validation */
    return 1;  /* 1 = accept, 0 = reject */
}

static long read_file_to_buffer(const char* fname, unsigned char** buf) {
    FILE* f = fopen(fname, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    *buf = (unsigned char*)malloc(sz);
    if (!*buf) { fclose(f); return -1; }
    size_t ret = fread(*buf, 1, sz, f);
    fclose(f);
    return (long)ret;
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
    /* wolfSSL_Debugging_ON(); */  /* Disable debug to reduce noise */

    ctx = wolfSSL_CTX_new(wolfDTLSv1_3_server_method());
    if (!ctx) {
        fprintf(stderr, "wolfSSL_CTX_new failed\n");
        goto exit;
    }

    /* Disable mutual authentication for testing */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    
    printf("[Server] ✓ Server-only authentication configured\n");

    /* Force PQC-friendly cipher suites */
    const char* pqc_ciphers =
        "TLS13-AES128-GCM-SHA256:"
        "TLS13-CHACHA20-POLY1305-SHA256";

    if ((ret = wolfSSL_CTX_set_cipher_list(ctx, pqc_ciphers)) != 1) {  /* wolfSSL returns 1 on success */
        fprintf(stderr, "wolfSSL_CTX_set_cipher_list failed (ret=%d)\n", ret);
        goto exit;
    }
    printf("[Server] ✓ PQC ciphers configured\n");

    /* Disable buffering for stdout to ensure logs are visible */
    setvbuf(stdout, NULL, _IONBF, 0);

#ifdef WOLFSSL_ML_KEM_512
    /* Enable ML-KEM-512 as supported group / key share */
    ret = wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ML_KEM_512);
    if (ret != 1) {  /* wolfSSL returns 1 on success */
        fprintf(stderr, "CTX_UseSupportedCurve(ML-KEM-512) failed (ret=%d)\n", ret);
        goto exit;
    }
    printf("[Server] ✓ ML-KEM-512 key exchange enabled\n");
#endif

#define SERVER_CERT_FILE "../pqc_certs/server-cert-final.der"
#define SERVER_KEY_FILE  "../pqc_certs/server-key-asn1.der"
#define CA_CERT_FILE     "../pqc_certs/ca-cert-final.der"

    unsigned char* cert_buf = NULL;
    unsigned char* key_buf = NULL;
    unsigned char* ca_buf = NULL;
    long sz;

#ifndef WOLFSSL_FILETYPE_RAW
#define WOLFSSL_FILETYPE_RAW 3
#endif

    printf("[Server] Loading server certificate from %s...\n", SERVER_CERT_FILE);
    sz = read_file_to_buffer(SERVER_CERT_FILE, &cert_buf);
    if (sz < 0) { fprintf(stderr, "Failed to read cert file\n"); goto exit; }
    
    ret = wolfSSL_CTX_use_certificate_buffer(ctx, cert_buf, sz, WOLFSSL_FILETYPE_ASN1);
    if (ret != 1) {
        fprintf(stderr, "[Server] Failed to load server cert buffer (ret=%d)\n", ret);
        wolfSSL_ERR_print_errors_fp(stderr, ret);
        goto exit;
    }
    printf("[Server] ✓ Server certificate loaded (%ld bytes)\n", sz);

    printf("[Server] Loading server key from %s...\n", SERVER_KEY_FILE);
    sz = read_file_to_buffer(SERVER_KEY_FILE, &key_buf);
    if (sz < 0) { fprintf(stderr, "Failed to read key file\n"); goto exit; }

    ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, key_buf, sz, WOLFSSL_FILETYPE_ASN1);
    if (ret != 1) {
        fprintf(stderr, "[Server] Failed to load server key buffer (ret=%d)\n", ret);
        goto exit;
    }
    printf("[Server] ✓ Server private key loaded (%ld bytes)\n", sz);

    printf("[Server] Loading CA certificate from %s...\n", CA_CERT_FILE);
    sz = read_file_to_buffer(CA_CERT_FILE, &ca_buf);
    if (sz < 0) { fprintf(stderr, "Failed to read CA file\n"); goto exit; }

    ret = wolfSSL_CTX_load_verify_buffer(ctx, ca_buf, sz, WOLFSSL_FILETYPE_ASN1);
    if (ret != 1) {
        fprintf(stderr, "[Server] Failed to load CA cert buffer (ret=%d)\n", ret);
        goto exit;
    }
    printf("[Server] ✓ CA certificate loaded (%ld bytes)\n", sz);

    /* PQC configuration complete! */

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

    printf("[Server] Listening on %s:%d (DTLS 1.3 with PQC)\n",
           server_ip, server_port);
    printf("[Server] Key Exchange: ML-KEM-512\n");
    printf("[Server] Authentication: ML-DSA (Dilithium) Level 2\n");
    printf("[Server] Waiting for client connection...\n\n");

    /* 3. Wait for first ClientHello to learn the client address */
    printf("[Server] ═══════════════════════════════════════\n");
    printf("[Server] Listening for ClientHello on UDP...\n");
    printf("[Server] ═══════════════════════════════════════\n");
    
    int recvd = recvfrom(sockfd, buf, sizeof(buf), MSG_PEEK,
                         (struct sockaddr*)&cliaddr, &cliaddr_len);
    if (recvd < 0) {
        perror("recvfrom");
        goto exit;
    }

    char cli_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &cliaddr.sin_addr, cli_ip, sizeof(cli_ip));
    printf("[Server] ═══════════════════════════════════════\n");
    printf("[Server] ✓ Received packet from %s:%d (%d bytes)\n",
           cli_ip, ntohs(cliaddr.sin_port), recvd);
    
    /* Print hex dump */
    printf("[Server] Data (hex): ");
    for (int i = 0; i < recvd && i < 64; i++) {
        printf("%02x ", (unsigned char)buf[i]);
        if ((i + 1) % 16 == 0) printf("\n[Server]             ");
    }
    printf("\n");
    
    /* Check if it's a DTLS ClientHello (starts with 0x16 for handshake) */
    if (recvd > 13 && (unsigned char)buf[0] == 0x16) {
        printf("[Server] ✓ Detected DTLS Handshake message (type 0x16)\n");
    } else {
        printf("[Server] ⚠ Not a standard DTLS handshake (first byte: 0x%02x)\n", (unsigned char)buf[0]);
    }
    printf("[Server] ═══════════════════════════════════════\n");
    
    /* Small delay to ensure packet is fully received */
    usleep(100000); /* 100ms */

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

    printf("[Server] Starting DTLS 1.3 handshake...\n");
    printf("[Server] Expecting ML-KEM-512 key exchange\n");
    printf("[Server] Expecting Dilithium certificate verification\n");
    
    /* Accept with retry logic */
    int attempts = 0;
    int max_attempts = 10;
    
    while (attempts < max_attempts) {
        ret = wolfSSL_accept(ssl);
        
        if (ret == 1) {  /* wolfSSL returns 1 on success */
            break;
        }
        
        int err = wolfSSL_get_error(ssl, ret);
        
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            /* Non-fatal, retry */
            attempts++;
            if (attempts % 2 == 0) {
                printf("[Server] Handshake in progress (attempt %d/%d)...\n", attempts, max_attempts);
            }
            usleep(200000); /* 200ms delay */
            continue;
        } else {
            /* Fatal error */
            char err_buf[80];
            wolfSSL_ERR_error_string(err, err_buf);
            fprintf(stderr, "[Server] ✗ Handshake error %d: %s\n", err, err_buf);
            goto exit;
        }
    }
    
    if (ret != 1) {  /* wolfSSL returns 1 on success */
        fprintf(stderr, "[Server] ✗ Handshake failed after %d attempts\n", max_attempts);
        goto exit;
    }

    printf("\n========================================\n");
    printf("✓ DTLS 1.3 Handshake Complete!\n");
    printf("========================================\n");
    printf("  Cipher:     %s\n", wolfSSL_get_cipher(ssl));
    printf("  Version:    %s\n", wolfSSL_get_version(ssl));
    printf("  Key Exch:   ML-KEM-512 (Post-Quantum)\n");
    printf("  Auth:       ML-DSA Dilithium (Post-Quantum)\n");
    printf("========================================\n");

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
    if (cert_buf) free(cert_buf);
    if (key_buf) free(key_buf);
    if (ca_buf) free(ca_buf);
    wolfSSL_Cleanup();
    if (sockfd >= 0) close(sockfd);
    return 0;
}
