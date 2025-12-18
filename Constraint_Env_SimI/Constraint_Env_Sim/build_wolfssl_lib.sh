#!/bin/bash
# Build minimal wolfSSL library for RISC-V bare-metal

set -e

WOLFSSL_ROOT="/home/neginegi/projects/ps/wolfssl"
BUILD_DIR="$(pwd)/wolfssl_build"
LIB_FILE="libwolfssl_minimal.a"

echo "========================================================================"
echo " Building Minimal WolfSSL Library for RISC-V"
echo "========================================================================"
echo ""

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Essential source files for DTLS 1.3 with PQC
ESSENTIAL_SRCS="
ssl.c
dtls.c
dtls13.c
tls.c
tls13.c
internal.c
keys.c
wolfio.c
"

CRYPT_SRCS="
aes.c
sha256.c
sha512.c
hmac.c
random.c
rsa.c
dilithium.c
wc_mlkem.c
wc_mlkem_poly.c
asn.c
coding.c
memory.c
wc_port.c
wc_encrypt.c
hash.c
"

CC="riscv64-unknown-elf-gcc"
AR="riscv64-unknown-elf-ar"

CFLAGS="-O2 -g -I. -I../wolfssl -I../wolfssl/wolfcrypt"
CFLAGS="$CFLAGS -I$WOLFSSL_ROOT -I$WOLFSSL_ROOT/wolfcrypt"
CFLAGS="$CFLAGS -I$(pwd)/boot"
CFLAGS="$CFLAGS -DUSER_SETTINGS_H -DHAVE_RPK -DSINGLE_THREADED"
CFLAGS="$CFLAGS -march=rv32im -mabi=ilp32"

echo "[1] Compiling SSL layer sources..."
for src in $ESSENTIAL_SRCS; do
    if [ -f "$WOLFSSL_ROOT/src/$src" ]; then
        echo "  Compiling $src..."
        $CC $CFLAGS -c "$WOLFSSL_ROOT/src/$src" -o "${src%.c}.o"
    fi
done

echo ""
echo "[2] Compiling WolfCrypt sources..."
for src in $CRYPT_SRCS; do
    if [ -f "$WOLFSSL_ROOT/wolfcrypt/src/$src" ]; then
        echo "  Compiling $src..."
        $CC $CFLAGS -c "$WOLFSSL_ROOT/wolfcrypt/src/$src" -o "${src%.c}.o"
    fi
done

echo ""
echo "[3] Creating static library..."
$AR rcs "$LIB_FILE" *.o

echo ""
echo "========================================================================"
echo " Library built successfully!"
echo "========================================================================"
ls -lh "$LIB_FILE"

echo ""
echo "Copy to boot directory:"
echo "  cp $BUILD_DIR/$LIB_FILE ../boot/"

echo ""
