#!/bin/bash
# Quick fix script to resolve wolfSSL linking issues

echo "========================================================================"
echo " WolfSSL Linking Diagnostic & Fix Script"
echo "========================================================================"
echo ""

# Check if wolfSSL root exists
WOLFSSL_ROOT="/home/neginegi/projects/ps/wolfssl"

echo "[1] Checking WolfSSL installation..."
if [ -d "$WOLFSSL_ROOT" ]; then
    echo "  ✓ Wolf SSL root found: $WOLFSSL_ROOT"
else
    echo "  ✗ WolfSSL root NOT found: $WOLFSSL_ROOT"
    echo "  Please set WOLFSSL_ROOT in boot/Makefile to correct path"
    exit 1
fi

# Check for library
echo ""
echo "[2] Checking for pre-compiled library..."
if [ -f "$WOLFSSL_ROOT/lib/libwolfssl.a" ]; then
    echo "  ✓ Found: $WOLFSSL_ROOT/lib/libwolfssl.a"
    HAVE_LIB=1
else
    echo "  ✗ Library not found: $WOLFSSL_ROOT/lib/libwolfssl.a"
    HAVE_LIB=0
fi

if [ -f "$WOLFSSL_ROOT/.libs/libwolfssl.a" ]; then
    echo "  ✓ Found: $WOLFSSL_ROOT/.libs/libwolfssl.a"
    HAVE_LIBS_DIR=1
else
    echo "  ✗ Not in .libs directory either"
    HAVE_LIBS_DIR=0
fi

# Check source files
echo ""
echo "[3] Checking WolfSSL source files..."
SSL_SRCS=$(find "$WOLFSSL_ROOT/src" -name "*.c" 2>/dev/null | wc -l)
CRYPT_SRCS=$(find "$WOLFSSL_ROOT/wolfcrypt/src" -name "*.c" 2>/dev/null | wc -l)

echo "  SSL sources: $SSL_SRCS files"
echo "  WolfCrypt sources: $CRYPT_SRCS files"

# Recommend solution
echo ""
echo "========================================================================"
echo " RECOMMENDED SOLUTION"
echo "========================================================================"
echo ""

if [ $HAVE_LIB -eq 1 ]; then
    echo "✓ Pre-compiled library exists - UPDATE MAKEFILE:"
    echo ""
    echo "Add to boot/Makefile after line 40:"
    echo "WOLFSSL_LIB = \$(WOLFSSL_ROOT)/lib/libwolfssl.a"
    echo "LDFLAGS += -L\$(WOLFSSL_ROOT)/lib"
    echo ""
    echo "And update the link command (line ~52):"
    echo "\$(CC) \$(LDFLAGS) -T linker.ld -N -o \$@ \\"
    echo "    \$(OBJECTS) \\"
    echo "    \$(WOLFSSL_LIB) \\"  # ← ADD THIS LINE
    echo "    \$(PACKAGES:%=-L\$(BUILD_DIR)/software/%) \\"
    echo "    ..."
    
elif [ $HAVE_LIBS_DIR -eq 1 ]; then
    echo "✓ Library in .libs directory - UPDATE MAKEFILE:"
    echo ""
    echo "Add to boot/Makefile:"
    echo "WOLFSSL_LIB = \$(WOLFSSL_ROOT)/.libs/libwolfssl.a"
    echo "And update link command to include \$(WOLFSSL_LIB)"
    
elif [ $SSL_SRCS -gt 0 ] && [ $CRYPT_SRCS -gt 0 ]; then
    echo "⚠ No pre-compiled library - COMPILE FROM SOURCES:"
    echo ""
    echo "Option A: Build WolfSSL library first (recommended):"
    echo "  cd $WOLFSSL_ROOT"
    echo "  ./configure --host=riscv64-unknown-elf \\"
    echo "              --enable-dtls13 \\"
    echo "              --enable-ml-kem \\"
    echo "              --enable-dilithium \\"
    echo "              --disable-shared \\"
    echo "              --enable-static"
    echo "  make"
    echo ""
    echo "Option B: Compile sources with firmware:"
    echo "  Uncomment lines 15 & 18 in boot/Makefile:"
    echo "  SRCS += \$(SRC_FILES)"
    echo "  SRCS += \$(wildcard \$(WOLFSSL_ROOT)/wolfcrypt/src/*.c)"
    echo ""
    echo "  Then add to OBJECTS:"
    echo "  OBJECTS += \$(notdir \$(SRCS:.c=.o))"
    echo ""
    echo "  And add VPATH:"
    echo "  VPATH += \$(WOLFSSL_ROOT)/src:\$(WOLFSSL_ROOT)/wolfcrypt/src"
else
    echo "✗ WolfSSL sources not found - INSTALLATION REQUIRED"
    echo ""
    echo "Clone and build WolfSSL:"
    echo "  git clone https://github.com/wolfSSL/wolfssl.git $WOLFSSL_ROOT"
    echo "  cd $WOLFSSL_ROOT"
    echo "  ./autogen.sh"
    echo "  ./configure --host=riscv64-unknown-elf ..."
    echo "  make"
fi

echo ""
echo "========================================================================"
echo " CURRENT MAKEFILE STATUS"
echo "========================================================================"
echo ""

cd boot 2>/dev/null || exit 1

echo "Lines with wolfSSL sources:"
grep -n "SRCS\|SRC_FILES" Makefile | head -5

echo ""
echo "Link command:"
grep -A5 "boot.elf:" Makefile | tail -6

echo ""
echo "========================================================================"
echo " QUICK TEST"
echo "========================================================================"
echo ""

echo "Testing if RISC-V toolchain can find wolfSSL headers..."
if riscv64-unknown-elf-gcc -I. -I./wolfssl -Iwolfssl/wolfcrypt \
   -DWOLFSSL_USER_SETTINGS -E -x c - <<< "#include <wolfssl/ssl.h>" \
   >/dev/null 2>&1; then
    echo "  ✓ Headers accessible"
else
    echo "  ✗ Headers not found - check include paths"
fi

echo ""
echo "Done! Follow the recommendations above to fix the linking issue."
echo ""
