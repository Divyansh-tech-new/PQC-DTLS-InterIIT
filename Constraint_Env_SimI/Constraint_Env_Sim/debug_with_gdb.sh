#!/bin/bash
# Debug firmware with GDB to find where wolfSSL_connect() hangs

set -e

echo "========================================"
echo "  GDB Debug Session for DTLS Firmware"
echo "========================================"
echo ""

# Kill any existing processes
pkill -9 -f "litex_sim|dtls_pqc_server|uart_udp_bridge" 2>/dev/null || true
sleep 2

# Start the simulation in background with GDB server
echo "[1/3] Starting LiteX simulation with GDB server..."
cd /home/neginegi/psI/82_PQC_DTLS_PS/Constraint_Env_SimI/Constraint_Env_Sim

timeout 180 python3 litex/litex/tools/litex_sim.py \
    --csr-json csr.json \
    --cpu-type=vexriscv \
    --cpu-variant=full \
    --integrated-main-ram-size=0x02000000 \
    --ram-init=boot.bin \
    --output-dir=build/sim_sp \
    --non-interactive \
    --with-gdb-stub \
    --gdb-port=3333 > logs/litex_gdb.log 2>&1 &

SIM_PID=$!
echo "  Simulation PID: $SIM_PID"

# Wait for GDB stub to be ready
echo "  Waiting for GDB stub to initialize..."
sleep 15

echo ""
echo "[2/3] Connecting GDB..."
echo ""

# Create GDB command script
cat > /tmp/gdb_commands.txt << 'EOF'
# Connect to GDB stub
target remote localhost:3333

# Load symbols from ELF
file boot.elf

# Set architecture for RISC-V
set architecture riscv:rv32

# Set breakpoints at key locations
break main
break run_dtls_client
break wolfSSL_connect
break wolfSSL_connect_TLSv13
break SendTls13ClientHello
break DoTls13ClientHello
break DoTls13HandShakeMsg

# Display useful info
set pagination off
set print pretty on

# Continue to main
continue

# When at main, continue to run_dtls_client
continue

# When at run_dtls_client, show context
list
info locals

# Continue to wolfSSL_connect
continue

# When at wolfSSL_connect, this is where it hangs
# Single-step through to find hang point
echo \n=== ENTERING wolfSSL_connect() ===\n
layout src
step 20

# If we get here, show backtrace
backtrace
info registers

# Continue execution
continue
EOF

echo "Starting GDB session..."
echo "Commands will be executed from /tmp/gdb_commands.txt"
echo ""

# Use gdb-multiarch which is available on this system
gdb-multiarch -x /tmp/gdb_commands.txt

echo ""
echo "[3/3] Cleaning up..."
kill $SIM_PID 2>/dev/null || true

echo ""
echo "========================================"
echo "  Debug session complete"
echo "========================================"
