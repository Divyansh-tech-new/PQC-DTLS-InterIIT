#!/bin/bash
# Test the bundled DTLS handshake flow

echo "========================================"
echo "  BUNDLED DTLS HANDSHAKE TEST"
echo "========================================"
echo ""

# Kill any existing processes
pkill -f "bundled_dtls|bundled_handshake_helper|litex_sim" 2>/dev/null
sleep 2

# Build bundled server
cd dtls_server
make -f Makefile.bundled clean
make -f Makefile.bundled
if [ $? -ne 0 ]; then
    echo "✗ Failed to build bundled server"
    exit 1
fi
cd ..

echo ""
echo "[1/3] Starting bundled DTLS server..."
./dtls_server/bundled_dtls_server > logs/bundled_server.log 2>&1 &
SERVER_PID=$!
sleep 2

echo "[2/4] Starting bundled handshake helper..."
python3 bundled_handshake_helper.py > logs/bundled_helper.log 2>&1 &
HELPER_PID=$!
sleep 2

echo "[3/4] Starting RISC-V simulation..."
echo "      (This will take 60-90 seconds for firmware to boot)"
echo ""

timeout 120 litex_sim --csr-json csr.json --cpu-type=vexriscv \
    --cpu-variant=full --integrated-main-ram-size=0x06400000 \
    --ram-init=boot.fbi > logs/bundled_sim.log 2>&1 &
SIM_PID=$!
sleep 5

echo "[4/4] Starting UART-UDP bridge..."
echo "      (Connecting simulation UART to helper)"
python3 uart_udp_bridge.py --tcp-port 1234 --udp-remote-port 5555 > logs/bundled_bridge.log 2>&1 &
BRIDGE_PID=$!
echo ""

# Monitor for success
echo "Monitoring handshake progress..."
for i in {1..90}; do
    sleep 1
    
    # Check helper log
    if grep -q "VERIFIED THE HANDSHAKE" logs/bundled_helper.log 2>/dev/null; then
        echo ""
        echo "========================================"
        echo "  ✓✓✓ SUCCESS! ✓✓✓"
        echo "========================================"
        cat logs/bundled_helper.log | grep -A 5 "VERIFIED"
        break
    fi
    
    # Progress indicator
    if [ $((i % 10)) -eq 0 ]; then
        echo "  ... waiting ${i}s ..."
    fi
done

# Cleanup
echo ""
echo "Cleaning up processes..."
kill $SERVER_PID $HELPER_PID $SIM_PID $BRIDGE_PID 2>/dev/null
pkill -f "bundled_dtls|bundled_handshake_helper|litex_sim|uart_udp_bridge" 2>/dev/null

echo ""
echo "Logs saved to:"
echo "  - logs/bundled_server.log"
echo "  - logs/bundled_helper.log"
echo "  - logs/bundled_sim.log"
echo "  - logs/bundled_bridge.log"
echo ""
