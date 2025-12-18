#!/bin/bash
#
# Quick End-to-End Pipeline Test
# Tests: RISC-V Sim -> UART Bridge -> UDP Echo Server
#

set -e

echo "================================================================================"
echo "  Quick Pipeline Test (No DTLS - Just Communication)"
echo "================================================================================"
echo ""

# Config
LITEX_TCP_PORT=1234
UDP_PORT=4444
LOG_DIR="logs"
mkdir -p "$LOG_DIR"

# Cleanup
pkill -f "litex_sim" 2>/dev/null || true
pkill -f "uart_udp_bridge" 2>/dev/null || true
pkill -f "test_udp_server" 2>/dev/null || true
sleep 2

echo "[1/3] Starting UDP Echo Server..."
python3 test_udp_server.py > "$LOG_DIR/udp_server.log" 2>&1 &
SERVER_PID=$!
echo "  PID: $SERVER_PID"
sleep 2

echo ""
echo "[2/3] Starting LiteX Simulation..."
echo "  (This takes ~60 seconds to build...)"
litex_sim \
    --csr-json csr.json \
    --cpu-type=vexriscv \
    --cpu-variant=full \
    --integrated-main-ram-size=0x06400000 \
    --ram-init=boot.fbi \
    > "$LOG_DIR/litex.log" 2>&1 &
SIM_PID=$!
echo "  PID: $SIM_PID"
echo "  Waiting for build..."
sleep 70

echo ""
echo "[3/3] Starting UART-UDP Bridge..."
python3 uart_udp_bridge.py \
    --tcp-host 127.0.0.1 \
    --tcp-port $LITEX_TCP_PORT \
    --udp-local-ip 127.0.0.1 \
    --udp-remote-ip 127.0.0.1 \
    --udp-remote-port $UDP_PORT \
    > "$LOG_DIR/bridge.log" 2>&1 &
BRIDGE_PID=$!
echo "  PID: $BRIDGE_PID"
sleep 3

echo ""
echo "================================================================================"
echo "  All components running!"
echo "================================================================================"
echo "  UDP Server:  PID $SERVER_PID (logs: $LOG_DIR/udp_server.log)"
echo "  LiteX Sim:   PID $SIM_PID (logs: $LOG_DIR/litex.log)"
echo "  Bridge:      PID $BRIDGE_PID (logs: $LOG_DIR/bridge.log)"
echo ""
echo "Monitoring for 60 seconds..."
echo "================================================================================"
echo ""

# Monitor
for i in {1..60}; do
    echo -n "."
    sleep 1
    
    if [ $((i % 10)) == 0 ]; then
        echo ""
        echo "[After ${i}s] Checking logs..."
        echo "  Bridge activity:"
        tail -3 "$LOG_DIR/bridge.log" 2>/dev/null || echo "    No activity"
        echo "  Server activity:"
        tail -3 "$LOG_DIR/udp_server.log" 2>/dev/null || echo "    No packets"
        echo ""
    fi
done

echo ""
echo "================================================================================"
echo "Final Status:"
echo "================================================================================"
tail -20 "$LOG_DIR/udp_server.log"
echo "================================================================================"

# Cleanup
kill $SERVER_PID $SIM_PID $BRIDGE_PID 2>/dev/null || true
