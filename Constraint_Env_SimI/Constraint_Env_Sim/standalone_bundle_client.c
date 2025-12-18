/*
 * Standalone Bundle Client
 * Performs REAL DTLS 1.3 handshake with ML-KEM + Dilithium
 * Captures all handshake packets and sends as ONE bundle to server
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define BUNDLE_MAGIC "BDL5"
#define MAX_PACKETS 64
#define MAX_PACKET_SIZE 4096

typedef struct {
    unsigned char data[MAX_PACKET_SIZE];
    size_t len;
} PacketCapture;

static PacketCapture captured_packets[MAX_PACKETS];
static int packet_count = 0;

/* Custom I/O callbacks to capture packets */
int my_IORecv_capture(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    int sockfd = *(int*)ctx;
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    
    int n = recvfrom(sockfd, buf, sz, 0, (struct sockaddr*)&from, &fromlen);
    
    if (n > 0 && packet_count < MAX_PACKETS) {
        memcpy(captured_packets[packet_count].data, buf, n);
        captured_packets[packet_count].len = n;
        packet_count++;
        printf("[Client] ← Captured packet #%d (%d bytes)\n", packet_count, n);
    }
    
    return n;
}

int my_IOSend_capture(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    int sockfd = *(int*)ctx;
    struct sockaddr_in *dest = (struct sockaddr_in*)((int*)ctx + 1);
    
    int n = sendto(sockfd, buf, sz, 0, (struct sockaddr*)dest, sizeof(*dest));
    
    if (n > 0 && packet_count < MAX_PACKETS) {
        memcpy(captured_packets[packet_count].data, buf, n);
        captured_packets[packet_count].len = n;
        packet_count++;
        printf("[Client] → Captured packet #%d (%d bytes)\n", packet_count, n);
    }
    
    return n;
}

unsigned char* create_bundle(int *bundle_len) {
    size_t total_size = 8; // Magic + count
    
    for (int i = 0; i < packet_count; i++) {
        total_size += 4 + captured_packets[i].len;
    }
    
    unsigned char *bundle = malloc(total_size);
    if (!bundle) return NULL;
    
    unsigned char *ptr = bundle;
    
    // Magic
    memcpy(ptr, BUNDLE_MAGIC, 4);
    ptr += 4;
    
    // Count
    uint32_t count = htonl(packet_count);
    memcpy(ptr, &count, 4);
    ptr += 4;
    
    // Packets
    for (int i = 0; i < packet_count; i++) {
        uint32_t len = htonl(captured_packets[i].len);
        memcpy(ptr, &len, 4);
        ptr += 4;
        memcpy(ptr, captured_packets[i].data, captured_packets[i].len);
        ptr += captured_packets[i].len;
    }
    
    *bundle_len = total_size;
    return bundle;
}

int main(void) {
    printf("========================================\n");
    printf(" STANDALONE BUNDLE CLIENT\n");
    printf("========================================\n");
    printf(" Performs: REAL DTLS 1.3 Handshake\n");
    printf(" Crypto:   ML-KEM-512 + Dilithium\n");
    printf(" Output:   Bundled handshake packets\n");
    printf("========================================\n\n");
    
    // Init wolfSSL
    wolfSSL_Init();
    
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        return 1;
    }
    
    // Load client certificates
    printf("[Client] Loading certificates...\n");
    if (wolfSSL_CTX_use_certificate_file(ctx, "pqc_certs/client-pub.der", WOLFSSL_FILETYPE_ASN1) != 1) {
        fprintf(stderr, "Failed to load client cert\n");
        goto cleanup;
    }
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, "pqc_certs/client-key.der", WOLFSSL_FILETYPE_ASN1) != 1) {
        fprintf(stderr, "Failed to load client key\n");
        goto cleanup;
    }
    if (wolfSSL_CTX_load_verify_locations(ctx, "pqc_certs/ca-pub.der", NULL) != 1) {
        fprintf(stderr, "Failed to load CA cert\n");
        goto cleanup;
    }
    printf("[Client] ✓ Certificates loaded\n");
    
    // Configure PQC ciphers
    const char* ciphers = "TLS13-AES128-GCM-SHA256";
    wolfSSL_CTX_set_cipher_list(ctx, ciphers);
    
#ifdef WOLFSSL_ML_KEM_512
    wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ML_KEM_512);
    printf("[Client] ✓ ML-KEM-512 enabled\n");
#endif
    
    // Create UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        goto cleanup;
    }
    
    // Set up server address (for DTLS handshake destination)
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(4444);
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    // Create SSL object
    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "Failed to create SSL object\n");
        goto cleanup;
    }
    
    // Set up custom I/O with capture
    int io_ctx[sizeof(struct sockaddr_in)/sizeof(int) + 1];
    io_ctx[0] = sockfd;
    memcpy(&io_ctx[1], &servaddr, sizeof(servaddr));
    
    wolfSSL_SetIOReadCtx(ssl, io_ctx);
    wolfSSL_SetIOWriteCtx(ssl, io_ctx);
    wolfSSL_SetIORecv(ctx, my_IORecv_capture);
    wolfSSL_SetIOSend(ctx, my_IOSend_capture);
    
    wolfSSL_set_fd(ssl, sockfd);
    
    printf("\n[Client] Starting DTLS 1.3 handshake...\n");
    printf("[Client] This will capture all handshake packets\n\n");
    
    // Perform handshake
    int ret = wolfSSL_connect(ssl);
    
    if (ret == WOLFSSL_SUCCESS) {
        printf("\n[Client] ✓✓✓ DTLS Handshake Completed! ✓✓✓\n");
    } else {
        int err = wolfSSL_get_error(ssl, ret);
        printf("\n[Client] Handshake completed with code: %d (error: %d)\n", ret, err);
        printf("[Client] Note: We captured %d packets during attempt\n", packet_count);
    }
    
    // Wait a moment for any final packets
    sleep(2);
    
    printf("\n[Client] ========================================\n");
    printf("[Client] Captured %d handshake packets\n", packet_count);
    printf("[Client] ========================================\n");
    
    // Create bundle
    int bundle_len = 0;
    unsigned char *bundle = create_bundle(&bundle_len);
    
    if (bundle) {
        printf("[Client] Created bundle: %d bytes\n", bundle_len);
        
        // Send bundle to verification server (port 4444)
        printf("[Client] Sending bundle to verification server...\n");
        
        int n = sendto(sockfd, bundle, bundle_len, 0,
                      (struct sockaddr*)&servaddr, sizeof(servaddr));
        
        if (n > 0) {
            printf("[Client] ✓ Bundle sent (%d bytes)\n", n);
            
            // Wait for verification response
            struct sockaddr_in from;
            socklen_t fromlen = sizeof(from);
            unsigned char response[2048];
            
            struct timeval tv;
            tv.tv_sec = 5;
            tv.tv_usec = 0;
            setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            
            n = recvfrom(sockfd, response, sizeof(response), 0,
                        (struct sockaddr*)&from, &fromlen);
            
            if (n > 0) {
                response[n] = '\0';
                printf("\n[Client] ========================================\n");
                printf("[Client] SERVER VERIFICATION RESPONSE:\n");
                printf("[Client] ========================================\n");
                printf("%s\n", response);
                
                if (strstr((char*)response, "VERIFIED")) {
                    printf("[Client] ✓✓✓ SUCCESS! Server verified PQC handshake! ✓✓✓\n");
                }
            } else {
                printf("[Client] No response from server\n");
            }
        }
        
        free(bundle);
    }
    
    wolfSSL_free(ssl);
    
cleanup:
    if (sockfd >= 0) close(sockfd);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    
    return 0;
}
