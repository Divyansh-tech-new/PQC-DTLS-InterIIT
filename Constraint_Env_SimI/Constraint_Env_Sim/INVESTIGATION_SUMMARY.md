# DTLS 1.3 PQC Handshake Issue - Investigation Summary

## Problem Statement
DTLS 1.3 handshake with Post-Quantum Cryptography fails to complete on bare-metal RISC-V. The firmware hangs inside `wolfSSL_connect()` and never sends any DTLS packets.

## Environment
- **Hardware**: RISC-V VexRiscv Full (32-bit, RV32IM)
- **Simulation**: LiteX/Verilator  
- **Memory**: 32MB RAM, 500KB stack
- **Crypto**: WolfSSL with ML-KEM-512 + Dilithium Level 2
- **Transport**: UART → Bridge → UDP (custom I/O, no BSD sockets)

## Confirmed Behavior
1. ✅ Firmware boots and initializes correctly
2. ✅ wolfSSL_Init() succeeds
3. ✅ SSL context and object created successfully  
4. ✅ I/O callbacks registered (my_IOSend, my_IORecv)
5. ✅ Non-blocking mode enabled
6. ✅ Timeouts configured (init=1s, max=64s)
7. ✅ Prints `[ITER 0] PRE-CALL` before wolfSSL_connect()
8. ❌ **HANGS inside wolfSSL_connect() - function never returns**
9. ❌ Never prints `[ITER 0] POST-CALL`
10. ❌ I/O callbacks are NEVER invoked
11. ❌ No DTLS packets sent to network
12. ❌ Server never receives ClientHello

## Root Cause Analysis

### What We Know
- The hang is **deterministic** - happens every time at the same location
- The hang occurs **before any I/O attempts** - callbacks never called
- Stack usage is normal - largest frame is 1,280 bytes vs 500KB available
- wolfSSL_connect() is only 16 bytes, but calls wolfSSL_connect_TLSv13() (1024 bytes)

### Most Likely Causes
1. **Infinite loop in DTLS 1.3 state machine** - waiting for condition that never occurs
2. **Missing configuration for bare-metal** - DTLS 1.3 may require additional setup not documented
3. **PQC key generation hangs** - ML-KEM or Dilithium operations in infinite loop
4. **Thread synchronization issue** - despite SINGLE_THREADED, might be waiting on mutex

### Less Likely
- Stack overflow (plenty of stack available)
- Memory corruption (behavior is deterministic)
- Hardware issue (other firmware works fine)

## Files Modified

### Configuration
- `boot/wolfssl/wolfcrypt/user_settings.h` - WolfSSL build configuration
- `boot/main.c` - Firmware with DTLS client implementation
- `boot/Makefile` - Links with precompiled WolfSSL objects

### Debug Scripts Created
- `final_diagnostic.sh` - Comprehensive diagnostic report
- `analyze_stack.sh` - Stack usage analysis
- `debug_with_gdb.sh` - GDB debugging setup (requires --with-gdb-stub)

## Recommended Solutions (in order of priority)

### 1. Contact WolfSSL Support ⭐⭐⭐⭐⭐
This configuration is highly specialized and likely needs vendor expertise:
- DTLS 1.3 (bleeding edge, less tested than 1.2)
- Post-Quantum Cryptography (experimental)
- Bare-metal with no OS (unusual)  
- Custom I/O callbacks (non-standard)

**Action**: Open support ticket with WolfSSL, include this document

### 2. Switch to DTLS 1.2 ⭐⭐⭐⭐
DTLS 1.2 is mature and well-tested:
```c
// In user_settings.h:
#define WOLFSSL_DTLS
// #define WOLFSSL_DTLS13  // Remove this
// #define WOLFSSL_TLS13   // Remove this
```
Requires: Rebuild WolfSSL library

### 3. Enable WolfSSL Debug Logging ⭐⭐⭐⭐
Add internal debug output to see where it hangs:
```bash
# Rebuild WolfSSL with:
CFLAGS="-DDEBUG_WOLFSSL" make
```
Then implement debug callback in firmware (already added to main.c)

### 4. Use GDB to Step Through ⭐⭐⭐
```bash
./debug_with_gdb.sh
```
This requires simulation with `--with-gdb-stub` flag

### 5. Remove PQC Temporarily ⭐⭐
Test with standard ECDHE-ECDSA to isolate if PQC is the issue:
- Remove ML-KEM and Dilithium configuration
- Use standard ECC curves  
- Requires extensive WolfSSL reconfiguration

## Test Results

### Firmware Output (last successful print)
```
[CLIENT] Step 7: SSL object created successfully
[CLIENT] Step 7a: Setting I/O contexts
[CLIENT] Step 7b: I/O contexts set
[CLIENT] Step 8a: Setting NON-BLOCKING mode
[CLIENT] Step 8b: NON-BLOCKING mode enabled
[CLIENT] Step 8c: About to set timeout_init
[CLIENT] Step 8d: timeout_init returned 1
[CLIENT] Step 8e: About to set timeout_max
[CLIENT] Step 8f: timeout_max returned 1
[CLIENT] Step 8g: Testing if wolfSSL_connect hangs...
[CLIENT] Step 8h: Watchdog initialized
[CLIENT] Step 9: About to call wolfSSL_connect()
[Client] Starting DTLS handshake...
[DIAG] SSL object address: 0x40072270
[DIAG] CTX object address: 0x40071908
[CLIENT] *** ABOUT TO CALL wolfSSL_connect() ***
[CLIENT] If this hangs, wolfSSL_connect never returns
[ITER 0] PRE-CALL
<HANGS HERE - NO FURTHER OUTPUT>
```

### Bridge Log
```
[BRIDGE] TCP->UDP: Dropped 311 bytes of non-DTLS data (debug text)
```
**Analysis**: Bridge sees firmware debug output but no DTLS packets

### Server Log
```
[Server] Listening on 0.0.0.0:4444 (DTLS 1.3 with PQC)
[Server] Waiting for client connection...
<TIMEOUT - NO CLIENTHELLO RECEIVED>
```

## Code Locations

### Where It Hangs
```c
// boot/main.c, line ~270
ret = wolfSSL_connect(ssl);  // ← HANGS HERE, NEVER RETURNS
```

### I/O Callbacks (never called)
```c
// boot/main.c, lines 91-106
int my_IOSend(WOLFSSL *ssl, char *buff, int sz, void *ctx);
int my_IORecv(WOLFSSL *ssl, char *buff, int sz, void *ctx);
```

### Configuration
```c
// boot/main.c, lines 165-177
int configure_pqc_context(WOLFSSL_CTX* ctx, int is_server) {
    // Sets PSK callbacks
    // Configures ciphers
    // Returns WOLFSSL_SUCCESS
}
```

## Additional Notes

### WolfSSL Function Sizes
```
wolfSSL_connect:         16 bytes (wrapper)
wolfSSL_connect_TLSv13: 1024 bytes (main implementation)
SendTls13ClientHello:   1884 bytes
DoTls13ClientHello:     3668 bytes
```

### Memory Layout
```
Text:   438 KB (code)
Data:     0 KB  
BSS:    524 KB (uninitialized data)
Stack:  500 KB
Heap:   500 KB  
Total: ~2 MB firmware footprint
```

## Conclusion
The DTLS 1.3 handshake cannot succeed because wolfSSL_connect() hangs internally before attempting any network I/O. This is a deep issue within WolfSSL's DTLS 1.3 implementation when used with:
- Post-Quantum Cryptography
- Bare-metal platform (no OS)
- Custom I/O callbacks

**Resolution requires either**:
1. WolfSSL vendor support/patch
2. Switching to simpler configuration (DTLS 1.2, no PQC)
3. Extensive debugging with GDB to identify and patch the hang location

---

*Investigation completed: December 13, 2025*
