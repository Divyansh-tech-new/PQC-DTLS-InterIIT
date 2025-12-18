#!/bin/bash
#
# Complete DTLS 1.3 Post-Quantum Cryptography Demo
# Runs: LiteX RISC-V Simulation + UART Bridge + DTLS Server
#

set -e

echo "================================================================================"
echo "  DTLS 1.3 with Post-Quantum Cryptography (Dilithium + ML-KEM)"
echo "  Certificate-based Mutual Authentication Demo"
echo "================================================================================"
echo ""

# Configuration
LITEX_TCP_PORT=1234
UDP_PORT=4444
LOG_DIR="logs"
TIMEOUT_DURATION=300

# Create log directory
mkdir -p "$LOG_DIR"

# Cleanup any existing processes
echo "[0/4] Cleaning up previous instances..."
pkill -f "litex_sim" 2>/dev/null || true
pkill -f "uart_udp_bridge" 2>/dev/null || true
pkill -f "dtls_pqc_server" 2>/dev/null || true
sleep 2

# Check if boot.fbi exists
if [ ! -f "boot.fbi" ]; then
    echo "ERROR: boot.fbi not found!"
    echo "Please build the firmware first using: ./build_dtls_firmware.sh"
    exit 1
fi

# Check if DTLS server exists
if [ ! -f "dtls_server/dtls_pqc_server" ]; then
    echo "ERROR: DTLS server binary not found!"
    echo "Building DTLS server..."
    cd dtls_server && make && cd ..
fi

echo ""
echo "[1/4] Starting DTLS PQC Server (Port $UDP_PORT)..."
cd dtls_server
./dtls_pqc_server > "../$LOG_DIR/dtls_server.log" 2>&1 &
SERVER_PID=$!
cd ..
echo "  ✓ Server PID: $SERVER_PID"
sleep 2

echo ""
echo "[2/4] Starting LiteX RISC-V Simulation..."
echo "  (Building and initializing... this takes ~60-90 seconds)"
export PYTHONPATH=$(find $PWD -maxdepth 1 -name "pythondata*" -type d | tr '\n' ':')litex:migen:$PYTHONPATH
timeout $TIMEOUT_DURATION python3 litex/litex/tools/litex_sim.py \
    --csr-json csr.json \
    --cpu-type=vexriscv \
    --cpu-variant=full \
    --integrated-main-ram-size=0x02000000 \
    --ram-init=boot/boot.bin \
    --non-interactive \
    < /dev/null > "$LOG_DIR/litex_sim.log" 2>&1 &
SIM_PID=$!
echo "  ✓ Simulation PID: $SIM_PID"
echo "  Waiting for RISC-V boot..."
sleep 15

echo ""
echo "[3/4] Starting UART-UDP Bridge..."
python3 uart_udp_bridge.py \
    --tcp-host 127.0.0.1 \
    --tcp-port $LITEX_TCP_PORT \
    --udp-local-ip 127.0.0.1 \
    --udp-remote-ip 127.0.0.1 \
    --udp-remote-port $UDP_PORT \
    > "$LOG_DIR/uart_bridge.log" 2>&1 &
BRIDGE_PID=$!
echo "  ✓ Bridge PID: $BRIDGE_PID"
sleep 3

echo ""
echo "================================================================================"
echo "  ALL COMPONENTS RUNNING!"
echo "================================================================================"
echo "  Component        | PID         | Log File"
echo "  ----------------|-------------|----------------------------------"
echo "  DTLS Server     | $SERVER_PID  | $LOG_DIR/dtls_server.log"
echo "  LiteX RISC-V    | $SIM_PID  | $LOG_DIR/litex_sim.log"
echo "  UART Bridge     | $BRIDGE_PID  | $LOG_DIR/uart_bridge.log"
echo "================================================================================"
echo ""
echo "[4/4] Monitoring DTLS Handshake (90 seconds)..."
echo ""

# Monitor for handshake completion
HANDSHAKE_SUCCESS=0
for i in {1..300}; do
    echo -n "."
    sleep 1
    
    # Check for handshake completion every 10 seconds
    if [ $((i % 10)) == 0 ]; then
        echo ""
        echo "[$i seconds] Checking handshake progress..."
        
        if grep -q "SSL_accept succeeded" "$LOG_DIR/dtls_server.log" 2>/dev/null; then
            echo "  ✓ DTLS HANDSHAKE SUCCESSFUL!"
            HANDSHAKE_SUCCESS=1
            break
        fi
        
        # Show recent activity
        echo "  Server activity:"
        tail -3 "$LOG_DIR/dtls_server.log" 2>/dev/null || echo "    Waiting..."
        echo ""
    fi
done

echo ""
echo "================================================================================"
echo "  FINAL RESULTS"
echo "================================================================================"
echo ""

if [ $HANDSHAKE_SUCCESS -eq 1 ]; then
    echo "✓✓✓ SUCCESS! DTLS 1.3 Post-Quantum Handshake Completed ✓✓✓"
    echo ""
    echo "Cryptographic Details:"
    echo "  - Key Exchange: ML-KEM (Kyber) hybrid"
    echo "  - Signatures: Dilithium (quantum-resistant)"
    echo "  - Cipher Suite: TLS_AES_128_GCM_SHA256"
    echo "  - Authentication: Mutual (Client + Server certificates)"
    echo ""
else
    echo "⚠ Handshake did not complete in expected time"
    echo "Check logs for details..."
fi

echo "Recent Server Log (last 30 lines):"
echo "--------------------------------------------------------------------------------"
tail -30 "$LOG_DIR/dtls_server.log"
echo "================================================================================"

# Keep running for a bit more to see data exchange
if [ $HANDSHAKE_SUCCESS -eq 1 ]; then
    echo ""
    echo "Monitoring secure communication for 20 more seconds..."
    sleep 20
fi

echo ""
echo "================================================================================"
echo "  Stopping all components..."
echo "================================================================================"
kill $SERVER_PID $SIM_PID $BRIDGE_PID 2>/dev/null || true
sleep 2
echo "✓ Demo complete!"
echo ""
echo "Full logs available in: $LOG_DIR/"
echo "================================================================================"
