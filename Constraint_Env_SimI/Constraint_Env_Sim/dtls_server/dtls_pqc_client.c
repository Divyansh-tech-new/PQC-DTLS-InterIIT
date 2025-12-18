#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

// Use PQC certs from ../pqc_certs
#define CA_CERT_FILE     "../pqc_certs/ca-cert-final.der"
#define CLIENT_CERT_FILE "../pqc_certs/client-cert-final.der"
#define CLIENT_KEY_FILE  "../pqc_certs/client-key-asn1.der"

/* Verification callback */
static int verify_callback(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    (void)store;
    printf("[Client] Certificate verification callback (preverify=%d)\n", preverify);
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

int main(int argc, char* argv[])
{
    int                 ret;
    int                 sockfd;
    struct sockaddr_in  servaddr;
    const char*         server_ip   = "127.0.0.1";
    const int           server_port = 4444; // Target port (Bridge UDP)

    unsigned char       buf[1500];
    WOLFSSL_CTX*        ctx = NULL;
    WOLFSSL*            ssl = NULL;

    printf("========================================\n");
    printf(" DTLS 1.3 PQC Client (Mutual Auth)\n");
    printf("========================================\n");

    /* 1. Init wolfSSL */
    wolfSSL_Init();
    /* wolfSSL_Debugging_ON(); */

    ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (!ctx) {
        fprintf(stderr, "wolfSSL_CTX_new failed\n");
        goto exit;
    }

    /* Verification settings */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, verify_callback);

    /* Ciphers */
    const char* pqc_ciphers = "TLS13-AES128-GCM-SHA256:TLS13-CHACHA20-POLY1305-SHA256";
    if (wolfSSL_CTX_set_cipher_list(ctx, pqc_ciphers) != 1) {
        fprintf(stderr, "wolfSSL_CTX_set_cipher_list failed\n");
        goto exit;
    }

    /* Disable output buffering */
    setvbuf(stdout, NULL, _IONBF, 0);

#ifdef WOLFSSL_ML_KEM_512
    /* Enable ML-KEM-512 group */
    if (wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ML_KEM_512) != 1) {
        fprintf(stderr, "CTX_UseSupportedCurve(ML-KEM-512) failed\n");
        goto exit;
    }
    printf("[Client] ✓ ML-KEM-512 enabled\n");
#endif

    /* Load Certs */
    unsigned char* cert_buf = NULL;
    unsigned char* key_buf = NULL;
    unsigned char* ca_buf = NULL;
    long sz;

    printf("[Client] Loading client certificate...\n");
    // Note: Assuming restore_certs.py created client keys correctly
    // or using server keys as client for testing if client ones fail
    // We will try client keys first.
    sz = read_file_to_buffer(CLIENT_CERT_FILE, &cert_buf);
    if (sz < 0) { 
        fprintf(stderr, "Failed to read client cert. Trying server cert as fallback...\n"); 
        sz = read_file_to_buffer("../pqc_certs/server-cert-final.der", &cert_buf);
        if (sz < 0) { fprintf(stderr, "Failed fallback too.\n"); goto exit; }
    }
    
    // We assume keys are in ASN1/DER format
    ret = wolfSSL_CTX_use_certificate_buffer(ctx, cert_buf, sz, WOLFSSL_FILETYPE_ASN1); 
    // Or RAW if restore_certs.py made them so? 
    // server used ASN1.
    if (ret != 1) {
        fprintf(stderr, "Failed to load cert buffer: %d\n", ret);
        goto exit;
    }

    printf("[Client] Loading client private key...\n");
    sz = read_file_to_buffer(CLIENT_KEY_FILE, &key_buf);
    if (sz < 0) {
         fprintf(stderr, "Failed to read client key. Trying server key...\n");
         sz = read_file_to_buffer("../pqc_certs/server-key-asn1.der", &key_buf);
    }
    
    ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, key_buf, sz, WOLFSSL_FILETYPE_ASN1);
    if (ret != 1) {
        fprintf(stderr, "Failed to load key buffer: %d\n", ret);
        goto exit;
    }

    printf("[Client] Loading CA certificate...\n");
    sz = read_file_to_buffer(CA_CERT_FILE, &ca_buf);
    ret = wolfSSL_CTX_load_verify_buffer(ctx, ca_buf, sz, WOLFSSL_FILETYPE_ASN1);
    if (ret != 1) {
        fprintf(stderr, "Failed to load CA cert buffer: %d\n", ret);
        goto exit;
    }

    /* 2. Create UDP socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) { perror("socket"); goto exit; }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family      = AF_INET;
    servaddr.sin_port        = htons(server_port);
    servaddr.sin_addr.s_addr = inet_addr(server_ip);

    /* Connect UDP socket to server (Bridge) */
    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect");
        goto exit;
    }

    /* 3. Create SSL */
    ssl = wolfSSL_new(ctx);
    if (!ssl) { fprintf(stderr, "wolfSSL_new failed\n"); goto exit; }
    
    wolfSSL_set_fd(ssl, sockfd);

    printf("[Client] Connecting to %s:%d...\n", server_ip, server_port);
    
    /* 4. Handshake */
    ret = wolfSSL_connect(ssl);
    if (ret != 1) {
        int err = wolfSSL_get_error(ssl, ret);
        char err_buf[80];
        wolfSSL_ERR_error_string(err, err_buf);
        fprintf(stderr, "[Client] Handshake error %d: %s\n", err, err_buf);
        goto exit;
    }

    printf("[Client] ✓ Handshake Success!\n");
    printf("  Cipher: %s\n", wolfSSL_get_cipher(ssl));

    /* 5. Send/Recv */
    const char* msg = "Hello from Desktop Client!";
    wolfSSL_write(ssl, msg, strlen(msg));
    printf("[Client] Sent: %s\n", msg);

    int recvd = wolfSSL_read(ssl, buf, sizeof(buf)-1);
    if (recvd > 0) {
        buf[recvd] = '\0';
        printf("[Client] Received: %s\n", buf);
    }

exit:
    if (ssl) wolfSSL_free(ssl);
    if (ctx) wolfSSL_CTX_free(ctx);
    if (cert_buf) free(cert_buf);
    if (key_buf) free(key_buf);
    if (ca_buf) free(ca_buf);
    wolfSSL_Cleanup();
    if (sockfd >= 0) close(sockfd);
    return 0;
}
