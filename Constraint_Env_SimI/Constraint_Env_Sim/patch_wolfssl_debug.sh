#!/bin/bash
# Patch WolfSSL with debug instrumentation and rebuild

set -e

WOLFSSL_SRC="/home/neginegi/projects/ps/wolfssl"
BACKUP_DIR="$(pwd)/wolfssl_backup_$(date +%Y%m%d_%H%M%S)"

echo "========================================"
echo " WolfSSL Debug Instrumentation"
echo "========================================"
echo ""

if [ ! -d "$WOLFSSL_SRC" ]; then
    echo "ERROR: WolfSSL source not found at $WOLFSSL_SRC"
    exit 1
fi

# Create backup
echo "[1/5] Creating backup..."
mkdir -p "$BACKUP_DIR"
cp "$WOLFSSL_SRC/src/ssl.c" "$BACKUP_DIR/ssl.c.backup"
if [ -f "$WOLFSSL_SRC/src/tls13.c" ]; then
    cp "$WOLFSSL_SRC/src/tls13.c" "$BACKUP_DIR/tls13.c.backup"
fi
echo "  Backup saved to: $BACKUP_DIR"

# Patch ssl.c - Add debug to wolfSSL_connect
echo ""
echo "[2/5] Patching ssl.c..."
sed -i '/if (ssl->options.tls1_3) {/a\
        printf("[WOLFSSL_DEBUG] wolfSSL_connect: Detected TLS 1.3\\n");\
        printf("[WOLFSSL_DEBUG] About to call wolfSSL_connect_TLSv13()\\n");' \
    "$WOLFSSL_SRC/src/ssl.c"
echo "  ✓ Added debug to wolfSSL_connect()"

# Patch tls13.c - Add debug to wolfSSL_connect_TLSv13
echo ""
echo "[3/5] Patching tls13.c..."
if [ -f "$WOLFSSL_SRC/src/tls13.c" ]; then
    # Find and patch the wolfSSL_connect_TLSv13 function
    # This is complex, so we'll create a more targeted patch
    
    # Add debug at function entry
    sed -i '/^int wolfSSL_connect_TLSv13/,/WOLFSSL_ENTER/{
        /WOLFSSL_ENTER/a\
    printf("[WOLFSSL_DEBUG] ==== ENTERED wolfSSL_connect_TLSv13 ====\\n");\
    printf("[WOLFSSL_DEBUG] SSL state: %d\\n", ssl ? ssl->options.connectState : -1);
    }' "$WOLFSSL_SRC/src/tls13.c"
    
    # Add debug before state machine loop
    sed -i '/while (ssl->options.connectState != CONNECT_FINISHED)/i\
    printf("[WOLFSSL_DEBUG] About to enter state machine loop\\n");\
    printf("[WOLFSSL_DEBUG] Initial connect state: %d\\n", ssl->options.connectState);' \
        "$WOLFSSL_SRC/src/tls13.c"
    
    echo "  ✓ Added debug to wolfSSL_connect_TLSv13()"
else
    echo "  ⚠ tls13.c not found, skipping"
fi

# Check patches applied
echo ""
echo "[4/5] Verifying patches..."
if grep -q "WOLFSSL_DEBUG" "$WOLFSSL_SRC/src/ssl.c"; then
    echo "  ✓ ssl.c patched successfully"
else
    echo "  ✗ ssl.c patch may have failed"
fi

if [ -f "$WOLFSSL_SRC/src/tls13.c" ]; then
    if grep -q "WOLFSSL_DEBUG" "$WOLFSSL_SRC/src/tls13.c"; then
        echo "  ✓ tls13.c patched successfully"
    else
        echo "  ✗ tls13.c patch may have failed"
    fi
fi

# Rebuild WolfSSL
echo ""
echo "[5/5] Rebuilding WolfSSL library..."
if [ -f ./build_wolfssl_lib.sh ]; then
    ./build_wolfssl_lib.sh
else
    echo "  ⚠ build_wolfssl_lib.sh not found"
    echo "  You need to rebuild manually"
fi

echo ""
echo "========================================"
echo " Patching Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "  1. Rebuild firmware: cd boot && make clean && make"
echo "  2. Run test: python3 soc_ethernet_sim.py"
echo ""
echo "To restore original WolfSSL:"
echo "  cp $BACKUP_DIR/*.backup $WOLFSSL_SRC/src/"
echo ""
