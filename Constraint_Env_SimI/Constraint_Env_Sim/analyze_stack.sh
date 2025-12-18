#!/bin/bash
# Analyze if stack overflow is causing the hang

echo "========================================"
echo "  Stack Usage Analysis"
echo "========================================"
echo ""

ELF_FILE="boot.elf"

if [ ! -f "$ELF_FILE" ]; then
    echo "ERROR: $ELF_FILE not found"
    exit 1
fi

echo "[1] Checking linker script for stack size..."
grep -A 2 "stack_size" boot/linker.ld || echo "No stack_size definition found"

echo ""
echo "[2] Analyzing symbol sizes..."
riscv64-unknown-elf-nm --size-sort --radix=d $ELF_FILE | tail -20

echo ""
echo "[3] Checking function sizes (largest first)..."
riscv64-unknown-elf-nm --size-sort --radix=d $ELF_FILE | grep " T " | tail -30

echo ""
echo "[4] Checking for large stack usage in functions..."
riscv64-unknown-elf-objdump -d $ELF_FILE | \
    grep -A 5 "addi.*sp,sp,-" | \
    grep "addi.*sp,sp,-[0-9]" | \
    sed 's/.*addi.*sp,sp,-//' | \
    sed 's/[^0-9].*//' | \
    sort -rn | \
    head -20 | \
    while read size; do
        echo "  Stack frame: $size bytes"
    done

echo ""
echo "[5] Total firmware size..."
ls -lh boot.bin

echo ""
echo "[6] ELF section sizes..."
riscv64-unknown-elf-size $ELF_FILE

echo ""
echo "========================================"
