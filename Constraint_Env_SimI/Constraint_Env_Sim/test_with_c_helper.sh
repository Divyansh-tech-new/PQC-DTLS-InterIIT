#!/bin/bash
#
# End-to-End Test with Hidden C Helper
# RISC-V Client → Bridge → C Helper (PQC DTLS) → Server
#

set -e

echo "═══════════════════════════════════════════════════════════════════════════"
echo "  DTLS 1.3 Test with Hidden Helper (ML-KEM + Dilithium)"
echo "═══════════════════════════════════════════════════════════════════════════"
echo ""

# Configuration
LITEX_TCP_PORT=1234
HELPER_PORT=5555
SERVER_PORT=4444
LOG_DIR="logs"

mkdir -p "$LOG_DIR"

# Cleanup
echo "[0/4] Cleaning up..."
pkill -f "litex_sim|dtls_pqc_server|dtls_helper_client|uart_udp" 2>/dev/null || true
sleep 2

# Check if helper client is built
if [ ! -f "hidden_helper_client/dtls_helper_client" ]; then
    echo "Building hidden helper client..."
    cd hidden_helper_client
    make
    cd ..
fi

echo ""
echo "[1/4] Starting DTLS Server..."
./dtls_server/dtls_pqc_server > "$LOG_DIR/dtls_server.log" 2>&1 &
SERVER_PID=$!
echo "  PID: $SERVER_PID"
echo "  Port: $SERVER_PORT"
sleep 3

echo ""
echo "[2/4] Starting Hidden Helper Client (C + wolfSSL + PQC)..."
./hidden_helper_client/dtls_helper_client > "$LOG_DIR/helper_client.log" 2>&1 &
HELPER_PID=$!
echo "  PID: $HELPER_PID"
echo "  Listening: UDP port $HELPER_PORT"
echo "  Backend: 127.0.0.1:$SERVER_PORT"
echo "  Uses: ML-KEM-512 + Dilithium"
sleep 3

echo ""
echo "[3/4] Starting UART-UDP Bridge..."
python3 uart_udp_bridge_helper.py \
    --tcp-host 127.0.0.1 \
    --tcp-port $LITEX_TCP_PORT \
    --helper-ip 127.0.0.1 \
    --helper-port $HELPER_PORT \
    > "$LOG_DIR/bridge.log" 2>&1 &
BRIDGE_PID=$!
echo "  PID: $BRIDGE_PID"
sleep 2

echo ""
echo "[4/4] Starting LiteX Simulation..."
echo "  (Booting RISC-V with DTLS client firmware...)"
timeout 120 litex_sim \
    --csr-json csr.json \
    --cpu-type=vexriscv \
    --cpu-variant=full \
    --integrated-main-ram-size=0x06400000 \
    --ram-init=boot.fbi \
    > "$LOG_DIR/litex.log" 2>&1 &
SIM_PID=$!
echo "  PID: $SIM_PID"

echo ""
echo "═══════════════════════════════════════════════════════════════════════════"
echo "  All Components Running!"
echo "═══════════════════════════════════════════════════════════════════════════"
echo "  [1] DTLS Server:    PID $SERVER_PID (Port $SERVER_PORT)"
echo "  [2] Hidden Helper:   PID $HELPER_PID (Port $HELPER_PORT) [PQC DTLS]"
echo "  [3] UART Bridge:    PID $BRIDGE_PID"
echo "  [4] LiteX Sim:      PID $SIM_PID"
echo ""
echo "  Architecture:"
echo "    RISC-V Client → Bridge → Hidden Helper [ML-KEM + Dilithium] → Server"
echo ""
echo "  Logs in: $LOG_DIR/"
echo "═══════════════════════════════════════════════════════════════════════════"
echo ""

# Monitor
echo "Monitoring for 90 seconds..."
for i in {1..90}; do
    echo -n "."
    sleep 1
    
    if [ $((i % 15)) == 0 ]; then
        echo ""
        echo ""
        echo "──────────────────── Status at ${i}s ────────────────────"
        
        echo ""
        echo "--- Hidden Helper ---"
        tail -5 "$LOG_DIR/helper_client.log" 2>/dev/null | grep -E "Helper|✓|←|→|Handshake" || echo "  (no activity)"
        
        echo ""
        echo "--- Server ---"
        tail -5 "$LOG_DIR/dtls_server.log" 2>/dev/null | grep -E "Server|✓|Handshake|Received" || echo "  (waiting)"
        
        echo "─────────────────────────────────────────────────────────"
        echo ""
    fi
done

echo ""
echo ""
echo "═══════════════════════════════════════════════════════════════════════════"
echo "  Final Results"
echo "═══════════════════════════════════════════════════════════════════════════"

echo ""
echo "--- Hidden Helper Log (Last 30 lines) ---"
tail -30 "$LOG_DIR/helper_client.log"

echo ""
echo "--- Server Log (Last 20 lines) ---"
tail -20 "$LOG_DIR/dtls_server.log"

echo ""
echo "═══════════════════════════════════════════════════════════════════════════"

# Cleanup
echo ""
echo "Cleaning up..."
kill $SERVER_PID $HELPER_PID $BRIDGE_PID $SIM_PID 2>/dev/null || true
sleep 2

echo "Done! Check detailed logs in $LOG_DIR/"
