#!/bin/bash
# Build script for DTLS PQC firmware

set -e

echo "Building DTLS PQC Firmware with Certificate-based Mutual Authentication..."

# Set build directory
BUILD_DIR="$(pwd)/build/sim_sp"
export BUILD_DIR

# Go to boot directory where our code is
cd boot

# Clean previous build
echo "Cleaning previous build..."
rm -f *.o src/*.o wolfcrypt/src/*.o boot.elf boot.bin boot.fbi 2>/dev/null || true

# Build the firmware
echo "Building firmware..."
make -j4

# Check if build succeeded
if [ -f boot.bin ]; then
    echo "✓ boot.bin created successfully"
    ls -lh boot.bin boot.elf
    
    # Copy to root directory (OVERWRITE existing files)
    cp boot.bin ../boot.bin
    cp boot.elf ../boot.elf
    
    # Create .fbi file for serial boot
    cd ..
    python3 -m litex.soc.software.crcfbigen boot.bin -o boot.fbi --fbi --little
    
    echo "✓ Firmware built successfully!"
    echo "  boot.bin - Raw binary (UPDATED)"
    echo "  boot.fbi - Format for serial boot"
    ls -lh boot.bin boot.fbi
else
    echo "✗ Build failed - boot.bin not created"
    exit 1
fi
