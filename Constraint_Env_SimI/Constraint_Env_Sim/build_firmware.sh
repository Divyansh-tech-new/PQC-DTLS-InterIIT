#!/bin/bash
#
# Build DTLS PQC Firmware - Creates boot.bin and boot.fbi
#

set -e

echo "================================================================================"
echo "  Building DTLS 1.3 Firmware with Post-Quantum Cryptography"
echo "================================================================================"
echo ""

# Check if we're in the right directory
if [ ! -d "boot" ]; then
    echo "ERROR: boot/ directory not found!"
    echo "Please run this script from the project root directory."
    exit 1
fi

# Go to boot directory
cd boot

echo "[1/3] Cleaning previous build..."
rm -f *.o *.d wolfcrypt/src/*.o boot.elf boot.bin boot.fbi 2>/dev/null || true
echo "  ✓ Clean complete"

echo ""
echo "[2/3] Compiling firmware..."
echo "  This includes wolfSSL with Dilithium + ML-KEM support..."
make -j$(nproc)

if [ ! -f "boot.bin" ]; then
    echo "✗ Build failed - boot.bin not created"
    exit 1
fi

echo "  ✓ Compilation successful"
echo ""
echo "[3/3] Creating bootable image..."

# Copy to root directory
cp boot.bin ../boot.bin
cp boot.elf ../boot.elf

cd ..

# Create .fbi file for LiteX simulation
python3 -m litex.soc.software.crcfbigen boot.bin -o boot.fbi --fbi --little

echo "  ✓ Bootable image created"
echo ""
echo "================================================================================"
echo "  BUILD COMPLETE!"
echo "================================================================================"
echo ""
echo "Generated files:"
ls -lh boot.bin boot.elf boot.fbi
echo ""
echo "To run the demo:"
echo "  ./run_demo.sh"
echo "================================================================================"
