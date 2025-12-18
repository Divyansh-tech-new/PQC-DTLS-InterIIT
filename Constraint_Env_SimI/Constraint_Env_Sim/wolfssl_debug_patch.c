/*
 * WolfSSL Debug Instrumentation Patch
 * 
 * This file contains printf statements to inject into wolfSSL source
 * to trace exactly where wolfSSL_connect() hangs.
 *
 * To apply: Manually add these printf statements to the WolfSSL source files
 */

/* ========================================
 * INSERT INTO: /home/neginegi/projects/ps/wolfssl/src/ssl.c
 * LOCATION: Inside wolfSSL_connect() function (around line 10350)
 * ======================================== */

// RIGHT AFTER: if (ssl->options.tls1_3) {
printf("[WOLFSSL_DEBUG] wolfSSL_connect: Detected TLS 1.3\n");
printf("[WOLFSSL_DEBUG] About to call wolfSSL_connect_TLSv13()\n");
return wolfSSL_connect_TLSv13(ssl);


/* ========================================
 * INSERT INTO: /home/neginegi/projects/ps/wolfssl/src/tls13.c  
 * LOCATION: Beginning of wolfSSL_connect_TLSv13() function
 * ======================================== */

printf("[WOLFSSL_DEBUG] ==== ENTERED wolfSSL_connect_TLSv13 ====\n");
printf("[WOLFSSL_DEBUG] SSL object: %p\n", (void*)ssl);
printf("[WOLFSSL_DEBUG] SSL state: %d\n", ssl ? ssl->options.connectState : -1);


/* ========================================
 * INSERT INTO: /home/neginegi/projects/ps/wolfssl/src/tls13.c
 * LOCATION: Inside wolfSSL_connect_TLSv13(), BEFORE state machine loop
 * Find: while (ssl->options.connectState != CONNECT_FINISHED)
 * ======================================== */

printf("[WOLFSSL_DEBUG] About to enter state machine loop\n");
printf("[WOLFSSL_DEBUG] Initial connect state: %d\n", ssl->options.connectState);

// Inside the while loop, at the TOP:
printf("[WOLFSSL_DEBUG] State machine iteration, state=%d\n", ssl->options.connectState);


/* ========================================
 * INSERT INTO: /home/neginegi/projects/ps/wolfssl/src/tls13.c
 * LOCATION: SendTls13ClientHello() function - at the beginning
 * ======================================== */

printf("[WOLFSSL_DEBUG] ==== ENTERED SendTls13ClientHello ====\n");
printf("[WOLFSSL_DEBUG] About to construct ClientHello message\n");


/* ========================================
 * INSERT INTO: /home/neginegi/projects/ps/wolfssl/src/dtls13.c
 * LOCATION: Dtls13RtxTimeout() or any DTLS13-specific retransmit functions
 * ======================================== */

printf("[WOLFSSL_DEBUG] DTLS 1.3 retransmit timeout handler called\n");


/* ========================================
 * COMPILE INSTRUCTIONS
 * ======================================== */

/*
To apply these patches manually:

1. Edit /home/neginegi/projects/ps/wolfssl/src/ssl.c
   - Find wolfSSL_connect() at line ~10350
   - Add printf at TLS 1.3 detection

2. Edit /home/neginegi/projects/ps/wolfssl/src/tls13.c
   - Find wolfSSL_connect_TLSv13()
   - Add printf at function entry
   - Add printf before state machine loop
   - Add printf inside state machine loop

3. Edit /home/neginegi/projects/ps/wolfssl/src/tls13.c
   - Find SendTls13ClientHello()
   - Add printf at function entry

4. Rebuild WolfSSL:
   cd /home/neginegi/psI/82_PQC_DTLS_PS/Constraint_Env_SimI/Constraint_Env_Sim
   ./build_wolfssl_lib.sh

5. Rebuild firmware:
   cd boot && make clean && make

6. Run test:
   python3 soc_ethernet_sim.py

The printf output will show exactly where execution stops.
*/
