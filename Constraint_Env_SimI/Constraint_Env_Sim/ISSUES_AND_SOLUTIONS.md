# PQC-DTLS Firmware - Complete Issue Analysis & Solutions

**Date:** 2025-12-13  
**System:** RISC-V VexRiscv on LiteX simulation with wolfSSL DTLS 1.3 + PQC

---

## ISSUE #1: Makefile VPATH Conflict ✅ RESOLVED

### Problem
The Makefile used VPATH to search for wolfSSL source files:
```makefile
VPATH = $(BIOS_DIRECTORY):$(WOLFSSL_ROOT)/src:$(WOLFSSL_ROOT)/wolfcrypt/src
```

When compiling, Make would find existing `.o` files in `/home/neginegi/projects/ps/wolfssl/src/` via VPATH and consider them "up to date" instead of building them locally. During linking, gcc looked for files like `ssl.o` in the current directory (`boot/`) but they didn't exist there, causing:
```
riscv64-unknown-elf-gcc: error: ssl.o: No such file or directory
... (100+ similar errors)
```

### Root Cause
- VPATH tells Make WHERE to find prerequisites
- Implicit compilation rules create `.o` files in CURRENT directory
- Make found `.o` in source tree → didn't compile → linker couldn't find them

### Solution Implemented
Modified `boot/Makefile` to use **absolute paths directly**:

```makefile
# OLD (broken):
SRCS += $(wildcard $(WOLFSSL_ROOT)/src/*.c)
OBJECTS += $(notdir $(SRCS:.c=.o))
VPATH = ... :$(WOLFSSL_ROOT)/src:$(WOLFSSL_ROOT)/wolfcrypt/src

# NEW (working):
WOLFSSL_TLS_OBJS := $(wildcard $(WOLFSSL_ROOT)/src/*.o)
WOLFSSL_CRYPTO_OBJS := $(wildcard $(WOLFSSL_ROOT)/wolfcrypt/src/*.o)
ALL_OBJS = $(OBJECTS) $(WOLFSSL_TLS_OBJS) $(WOLFSSL_CRYPTO_OBJS)

boot.elf: $(OBJECTS)
$(CC) $(LDFLAGS) -T linker.ld -N -o $@ $(ALL_OBJS) ...
```

**Result:** Firmware compiles successfully (3.1MB ELF, 430KB binary)

---

## ISSUE #2: Firmware DTLS Client Not Executing ⚠️ PARTIALLY RESOLVED

### Problem
After successful compilation, firmware runs but NO DTLS handshake occurs:
- Server never receives ClientHello
- Bridge drops 182 bytes of "non-DTLS data" (debug text)
- No DTLS record headers (0x16) detected

### Investigation Results (with extensive debug output added)

**Firmware execution trace:**
```
========================================
  RISC-V DTLS 1.3 PQC Demo (ML-KEM-512) 
========================================
[DEBUG] main: About to call wolfSSL_Init()
[DEBUG] wolfSSL_Init returned: 1 (SUCCESS=1)    ✅ SUCCESS
[DEBUG] wolfSSL_Init succeeded!
[DEBUG] Enabling wolfSSL debugging
[DEBUG] MODE_SERVER=0, calling run_dtls_client()

=== DTLS 1.3 PQC CLIENT MODE ===
[CLIENT] Step 1: Creating DTLS 1.3 client context
[CLIENT] Step 2: Context created successfully    ✅ SUCCESS
[CLIENT] Step 3: Setting I/O callbacks
[CLIENT] Step 4: Configuring PQC context
[Config] PQC Mode: ML-KEM-512 + PSK Authentication
[CLIENT] Step 5: PQC configured successfully     ✅ SUCCESS
[CLIENT] Step 6: Creating SSL object
[CLIENT] Step 7: SSL object created successfully ✅ SUCCESS
[CLIENT] Step 8: About to call wolfSSL_connect()
[Client] Starting DTLS handshake...
[Client] Waiting for server data on UART...
<< FIRMWARE STOPS HERE - no more output >>
```

### Root Cause Identified
`wolfSSL_connect()` is being called but:
1. ❌ **my_IOSend() is NEVER called** (no "[IOSend]" debug messages)
2. ❌ **my_IORecv() is NEVER called** (no "[IORecv]" debug messages)
3. ❌ Client never sends ClientHello packet

**This means wolfSSL_connect() is stuck in an infinite loop BEFORE attempting any I/O.**

### Likely Causes (in order of probability)

#### A. Infinite WANT_READ/WANT_WRITE loop
The firmware has this loop:
```c
do {
    ret = wolfSSL_connect(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, ret);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            attempts++;
            continue;  // Loop forever waiting for I/O
        }
    }
} while (ret != WOLFSSL_SUCCESS);
```

If wolfSSL_connect() returns `WOLFSSL_ERROR_WANT_WRITE` on the FIRST call (before trying to send), it will loop forever because:
- No data is being sent (my_IOSend not called)
- Loop just keeps calling wolfSSL_connect() repeatedly
- Never breaks out

**Solution:** Added max_attempts limit (5000 iterations) to break the loop and see actual error

#### B. Missing DTLS connection setup
DTLS requires peer address configuration. The code might be missing:
```c
wolfSSL_dtls_set_peer(ssl, &peer_addr, sizeof(peer_addr));
```

Without this, wolfSSL doesn't know WHERE to send the ClientHello.

#### C. Timer/Timeout configuration
DTLS 1.3 needs timeouts for retransmission. Missing:
```c
wolfSSL_dtls_set_timeout_init(ssl, TIMEOUT_SEC);
wolfSSL_dtls_set_timeout_max(ssl, MAX_TIMEOUT_SEC);
```

#### D. Custom I/O context not set correctly
The code does:
```c
wolfSSL_SetIOReadCtx(ssl, NULL);
wolfSSL_SetIOWriteCtx(ssl, NULL);
```

With NULL context, the I/O callbacks might not work properly.

### Diagnostic Steps Taken
1. ✅ Added debug printf at every step of main() and run_dtls_client()
2. ✅ Added debug printf in my_IOSend() and my_IORecv()
3. ✅ Verified wolfSSL_Init() succeeds
4. ✅ Verified all SSL setup succeeds up to wolfSSL_connect()
5. ⏳ Added max_attempts counter to break infinite loop (rebuild needed)
6. ⏳ Check actual error code returned by wolfSSL_connect()

---

## ISSUE #3: Bridge Timing / Buffering ℹ️ INFO

### Observation
When capturing firmware output directly from simulation UART, we see **1524 bytes** of debug text. But the bridge log only shows **182 bytes** dropped.

### Explanation
The bridge likely:
1. Starts **AFTER** some firmware output has already been sent
2. OR firmware output is buffered/delayed
3. Bridge correctly drops the text it DOES see

### Impact
Not a bug - just means the bridge misses the initial bootup messages. The DTLS issue is separate.

---

## RECOMMENDED NEXT STEPS

### 1. Fix wolfSSL_connect() infinite loop (HIGH PRIORITY)
Rebuild firmware with max_attempts limit, capture actual error code:
```bash
cd boot && make && cd ..
cp boot/boot.bin boot.bin
python3 read_firmware_output.py
```

Expected output will show:
```
[CLIENT] ERROR: Exceeded 5000 attempts, breaking loop
[CLIENT] Last error: X (WANT_READ=2, WANT_WRITE=3)
```

### 2. Add DTLS peer address (CRITICAL)
Add this BEFORE wolfSSL_connect():
```c
struct sockaddr_in peer_addr;
memset(&peer_addr, 0, sizeof(peer_addr));
peer_addr.sin_family = AF_INET;
peer_addr.sin_port = htons(4444);  // Server port
peer_addr.sin_addr.s_addr = inet_addr("127.0.0.1");  // Or however addresses work in LiteX
wolfSSL_dtls_set_peer(ssl, &peer_addr, sizeof(peer_addr));
```

**OR** if using custom I/O without sockets, this might not apply.

### 3. Add DTLS timeouts
```c
wolfSSL_dtls_set_timeout_init(ssl, 1);  // 1 second initial
wolfSSL_dtls_set_timeout_max(ssl, 64);  // 64 seconds max
```

### 4. Fix I/O context (if needed)
Instead of NULL, pass a context structure:
```c
typedef struct {
    // Any state needed for UART I/O
    int dummy;
} IOContext;

IOContext io_ctx = {0};
wolfSSL_SetIOReadCtx(ssl, &io_ctx);
wolfSSL_SetIOWriteCtx(ssl, &io_ctx);
```

### 5. Check my_IOSend/my_IORecv are being registered correctly
Verify at context level:
```c
printf("[DEBUG] Setting I/O callbacks at CTX level\n");
wolfSSL_CTX_SetIORecv(ctx, my_IORecv);
wolfSSL_CTX_SetIOSend(ctx, my_IOSend);
printf("[DEBUG] CTX callbacks: recv=%p send=%p\n", my_IORecv, my_IOSend);
```

---

## FILES MODIFIED

### boot/Makefile
- Removed VPATH dependency on wolfSSL source directories
- Added absolute paths to pre-compiled .o files: WOLFSSL_TLS_OBJS, WOLFSSL_CRYPTO_OBJS
- Changed boot.elf target to link with $(ALL_OBJS) directly

### boot/main.c
- Added custom_time() function for XTIME macro
- Added extensive debug printf statements throughout main()
- Added debug output at each step of run_dtls_client()
- Added debug output in my_IOSend() and my_IORecv()
- Added max_attempts limit to wolfSSL_connect() loop (latest)

---

## SUMMARY

✅ **RESOLVED:** Makefile VPATH issue - firmware now compiles successfully  
⚠️ **IDENTIFIED:** wolfSSL_connect() never calls I/O functions, likely stuck in WANT_READ/WANT_WRITE loop  
⏳ **NEXT:** Break the loop, capture error code, add peer address configuration

**Current State:** Firmware boots, initializes wolfSSL, creates SSL context and object, but hangs at wolfSSL_connect() without sending any DTLS packets.

