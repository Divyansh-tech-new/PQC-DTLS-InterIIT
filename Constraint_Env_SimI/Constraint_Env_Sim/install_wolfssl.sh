#!/bin/bash
#
# Build and Install wolfSSL with PQC Support
# This enables Dilithium and ML-KEM for DTLS 1.3
#

set -e

# Use system PATH to find build tools
export PATH="/usr/bin:/bin:/usr/local/bin:$PATH"

# Get the wolfssl directory (assumes it's in parent or sibling directory)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WOLFSSL_DIR="${WOLFSSL_DIR:-/usr/local/src/wolfssl}"
BUILD_DIR="/tmp/wolfssl_build"
INSTALL_PREFIX="/usr/local"

echo "========================================================================"
echo "  Building wolfSSL with Post-Quantum Cryptography Support"
echo "========================================================================"
echo ""
echo "Source:  $WOLFSSL_DIR"
echo "Install: $INSTALL_PREFIX"
echo ""
echo "Enabled Features:"
echo "  • DTLS 1.3"
echo "  • Dilithium (Level 2, 3, 5)"
echo "  • ML-KEM (Kyber) 512/768/1024"
echo "  • AES-GCM, ChaCha20-Poly1305"
echo "  • Certificate verification"
echo ""
echo "========================================================================"
echo ""

# Check if source exists
if [ ! -d "$WOLFSSL_DIR" ]; then
    echo "ERROR: wolfSSL source not found at $WOLFSSL_DIR"
    exit 1
fi

echo "[1/6] Preparing build directory..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$WOLFSSL_DIR"

echo "[2/6] Running autogen.sh to generate configure script..."
./autogen.sh

echo ""
echo "[3/6] Configuring wolfSSL with PQC options..."
echo "This may take a few minutes..."
echo ""

./configure \
    --prefix="$INSTALL_PREFIX" \
    --enable-dtls \
    --enable-dtls13 \
    --enable-dilithium \
    --enable-kyber \
    --enable-curve25519 \
    --enable-ed25519 \
    --enable-aesgcm \
    --enable-chacha \
    --enable-poly1305 \
    --enable-tlsx \
    --enable-supportedcurves \
    --enable-session-ticket \
    --enable-opensslextra \
    --enable-opensslall \
    CFLAGS="-DHAVE_DILITHIUM -DWOLFSSL_WC_DILITHIUM -DWOLFSSL_DILITHIUM_NO_LARGE_CODE -DWOLFSSL_HAVE_KYBER"

if [ $? -ne 0 ]; then
    echo ""
    echo "ERROR: Configure failed!"
    echo "Check if all dependencies are installed:"
    echo "  sudo apt-get install build-essential autoconf automake libtool"
    exit 1
fi

echo ""
echo "[4/6] Building wolfSSL..."
echo "This will take several minutes..."
echo ""

make -j$(nproc)

if [ $? -ne 0 ]; then
    echo ""
    echo "ERROR: Build failed!"
    exit 1
fi

echo ""
echo "[5/6] Installing wolfSSL (requires sudo)..."
echo ""

sudo make install

if [ $? -ne 0 ]; then
    echo ""
    echo "ERROR: Installation failed!"
    exit 1
fi

echo ""
echo "[6/6] Updating library cache..."
sudo ldconfig

echo ""
echo "========================================================================"
echo "  ✓ wolfSSL Installation Complete!"
echo "========================================================================"
echo ""

# Verify installation
if ldconfig -p | grep -q libwolfssl; then
    echo "✓ libwolfssl found in system libraries"
    ldconfig -p | grep libwolfssl
else
    echo "WARNING: libwolfssl not found in cache"
    echo "You may need to add $INSTALL_PREFIX/lib to LD_LIBRARY_PATH"
fi

echo ""
echo "Installation details:"
echo "  Headers:   $INSTALL_PREFIX/include/wolfssl"
echo "  Libraries: $INSTALL_PREFIX/lib/libwolfssl.*"
echo ""

# Check version
if [ -f "$INSTALL_PREFIX/bin/wolfssl-config" ]; then
    echo "wolfSSL version:"
    "$INSTALL_PREFIX/bin/wolfssl-config" --version || true
fi

echo ""
echo "Next steps:"
echo "  1. Rebuild DTLS server: cd dtls_server && make clean && make"
echo "  2. Run complete demo: ./run_complete_demo.sh"
echo ""
echo "========================================================================"
