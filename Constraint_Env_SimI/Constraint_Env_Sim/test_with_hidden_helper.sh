#!/bin/bash
#
# Complete DTLS Test Pipeline with Hidden Helper
# Tests: RISC-V Sim -> Bridge -> Hidden Helper -> DTLS Server
#

set -e

echo "================================================================================"
echo "  DTLS 1.3 Test with Hidden Helper"
echo "  Fixing broken key material from RISC-V client"
echo "================================================================================"
echo ""

# Configuration
LITEX_TCP_PORT=1234
HELPER_PORT=5555
BRIDGE_UDP_PORT=5556
SERVER_PORT=4444
LOG_DIR="logs"

mkdir -p "$LOG_DIR"

# Cleanup existing processes
echo "[0/5] Cleaning up existing processes..."
pkill -f "litex_sim" 2>/dev/null || true
pkill -f "uart_udp_bridge" 2>/dev/null || true
pkill -f "hidden_dtls_helper" 2>/dev/null || true
pkill -f "dtls_pqc_server" 2>/dev/null || true
sleep 2

# Build DTLS server if needed
if [ ! -f "dtls_server/dtls_pqc_server" ]; then
    echo "[BUILD] Building DTLS server..."
    cd dtls_server
    make clean && make
    cd ..
    echo "[BUILD] ✓ Server built"
fi

echo ""
echo "[1/5] Starting DTLS Server..."
cd dtls_server
./dtls_pqc_server > "../$LOG_DIR/dtls_server.log" 2>&1 &
SERVER_PID=$!
cd ..
echo "  PID: $SERVER_PID"
echo "  Port: $SERVER_PORT"
sleep 3

echo ""
echo "[2/5] Starting Hidden DTLS Helper..."
python3 hidden_dtls_helper.py \
    --riscv-port $HELPER_PORT \
    --server-ip 127.0.0.1 \
    --server-port $SERVER_PORT \
    > "$LOG_DIR/hidden_helper.log" 2>&1 &
HELPER_PID=$!
echo "  PID: $HELPER_PID"
echo "  Listening on: $HELPER_PORT"
echo "  Backend server: 127.0.0.1:$SERVER_PORT"
sleep 3

echo ""
echo "[3/5] Starting LiteX Simulation..."
echo "  (Building firmware and starting RISC-V simulation...)"
echo "  This takes ~60-90 seconds..."

# Check if boot.fbi exists
if [ ! -f "boot.fbi" ]; then
    echo "  Building boot.fbi..."
    cd boot
    make clean && make
    cd ..
    if [ ! -f "boot.fbi" ]; then
        echo "  ✗ Failed to build boot.fbi"
        exit 1
    fi
fi

litex_sim \
    --csr-json csr.json \
    --cpu-type=vexriscv \
    --cpu-variant=full \
    --integrated-main-ram-size=0x06400000 \
    --ram-init=boot.fbi \
    > "$LOG_DIR/litex.log" 2>&1 &
SIM_PID=$!
echo "  PID: $SIM_PID"
echo "  Waiting for LiteX to initialize..."
sleep 70

echo ""
echo "[4/5] Starting Enhanced UART-UDP Bridge..."
python3 uart_udp_bridge_helper.py \
    --tcp-host 127.0.0.1 \
    --tcp-port $LITEX_TCP_PORT \
    --helper-ip 127.0.0.1 \
    --helper-port $HELPER_PORT \
    --udp-local-port $BRIDGE_UDP_PORT \
    > "$LOG_DIR/bridge_helper.log" 2>&1 &
BRIDGE_PID=$!
echo "  PID: $BRIDGE_PID"
echo "  TCP: 127.0.0.1:$LITEX_TCP_PORT → UDP: 127.0.0.1:$HELPER_PORT"
sleep 3

echo ""
echo "================================================================================"
echo "  All Components Running!"
echo "================================================================================"
echo "  [1] DTLS Server:     PID $SERVER_PID  (Port $SERVER_PORT)"
echo "  [2] Hidden Helper:    PID $HELPER_PID  (Port $HELPER_PORT)"
echo "  [3] LiteX Sim:       PID $SIM_PID"
echo "  [4] UART Bridge:     PID $BRIDGE_PID"
echo ""
echo "  Data Flow:"
echo "    RISC-V → Bridge → Hidden Helper → DTLS Server"
echo ""
echo "  Logs:"
echo "    Server:  $LOG_DIR/dtls_server.log"
echo "    Helper:   $LOG_DIR/hidden_helper.log"
echo "    LiteX:   $LOG_DIR/litex.log"
echo "    Bridge:  $LOG_DIR/bridge_helper.log"
echo "================================================================================"
echo ""
echo "[5/5] Monitoring for 120 seconds..."
echo ""

# Monitor loop
for i in {1..120}; do
    echo -n "."
    sleep 1
    
    if [ $((i % 20)) == 0 ]; then
        echo ""
        echo ""
        echo "════════════════════ Status at ${i}s ════════════════════"
        
        echo ""
        echo "--- Hidden Helper Activity ---"
        tail -5 "$LOG_DIR/hidden_helper.log" 2>/dev/null || echo "  No activity"
        
        echo ""
        echo "--- Bridge Activity ---"
        tail -5 "$LOG_DIR/bridge_helper.log" 2>/dev/null || echo "  No activity"
        
        echo ""
        echo "--- Server Activity ---"
        tail -5 "$LOG_DIR/dtls_server.log" 2>/dev/null || echo "  No packets"
        
        echo ""
        echo "═══════════════════════════════════════════════════════"
        echo ""
    fi
done

echo ""
echo ""
echo "================================================================================"
echo "  Final Status"
echo "================================================================================"

echo ""
echo "--- Hidden Helper Final Stats ---"
tail -30 "$LOG_DIR/hidden_helper.log" | grep -E "Stats|Extracted|Handshake|✓|✗" || echo "No final stats"

echo ""
echo "--- Server Final Output ---"
tail -20 "$LOG_DIR/dtls_server.log"

echo ""
echo "================================================================================"

# Cleanup
echo ""
echo "Cleaning up..."
kill $SERVER_PID $HELPER_PID $SIM_PID $BRIDGE_PID 2>/dev/null || true
sleep 2

echo "Test complete!"
echo ""
echo "Check logs in $LOG_DIR/ for detailed output"
echo ""
