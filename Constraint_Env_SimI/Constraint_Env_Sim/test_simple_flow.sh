#!/bin/bash
# Simple test to verify data flow without DTLS handshake

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Testing data flow: RISC-V → Bridge → Helper → Server"
echo ""

# Kill existing processes
pkill -f "dtls|helper|bridge|test" 2>/dev/null || true
sleep 2

# Start simple UDP echo server on port 4444
echo "[1] Starting simple UDP echo server on port 4444..."
python3 -c "
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', 4444))
print('[Server] Listening on UDP 4444...')
while True:
    data, addr = sock.recvfrom(2048)
    print(f'[Server] Received {len(data)} bytes from {addr}')
    print(f'[Server] Data (hex): {data[:64].hex()}')
    print(f'[Server] Data (ascii): {data[:64]}')
    sock.sendto(b'ACK:' + data, addr)
" > logs/simple_server.log 2>&1 &
SERVER_PID=$!
echo "  PID: $SERVER_PID"
sleep 2

# Start helper (will fail cert load but still listen)
echo "[2] Starting helper on port 5555..."
./hidden_helper_client/dtls_helper_client > logs/simple_helper.log 2>&1 &
HELPER_PID=$!
echo "  PID: $HELPER_PID"
sleep 3

# Send test data to helper
echo "[3] Sending test data to helper..."
echo "KEY:test:16:1234567890123456" | nc -u -w1 127.0.0.1 5555

sleep 3

# Check logs
echo ""
echo "========== Helper Log =========="
tail -30 logs/simple_helper.log

echo ""
echo "========== Server Log =========="
tail -30 logs/simple_server.log

# Cleanup
kill $SERVER_PID $HELPER_PID 2>/dev/null || true
