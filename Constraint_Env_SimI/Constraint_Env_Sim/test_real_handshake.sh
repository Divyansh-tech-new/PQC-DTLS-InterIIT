#!/bin/bash

echo "════════════════════════════════════════════════════════════════"
echo "  REAL DTLS 1.3 PQC HANDSHAKE TEST"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "This will perform a REAL handshake between:"
echo "  • DTLS 1.3 Server (with PQC support)"
echo "  • DTLS 1.3 Client (with PQC support)"
echo "  • Using ML-KEM-512 key exchange"
echo "  • Using Dilithium signatures"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo ""

# Cleanup
echo "[Step 1] Cleaning up..."
pkill -f "dtls_pqc_server|dtls_pqc_client|tcpdump" 2>/dev/null
sleep 2
mkdir -p captures logs
echo "         ✓ Ready"
echo ""

# Start packet capture
echo "[Step 2] Starting packet capture..."
sudo timeout 30 tcpdump -i lo -w captures/real_handshake.pcap udp port 4444 > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1
echo "         ✓ Capturing on port 4444"
echo ""

# Start DTLS server
echo "[Step 3] Starting DTLS 1.3 PQC Server..."
./dtls_server/dtls_pqc_server > logs/real_server.log 2>&1 &
SERVER_PID=$!
sleep 2

if ! ps -p $SERVER_PID > /dev/null 2>&1; then
    echo "         ✗ Server failed to start"
    cat logs/real_server.log
    exit 1
fi

echo "         ✓ Server running (PID: $SERVER_PID)"
echo "           Listening on UDP port 4444"
echo ""

# Wait a bit more for server to be ready
sleep 1

# Run DTLS client
echo "[Step 4] Starting DTLS 1.3 PQC Client..."
echo "         Initiating handshake..."
timeout 10 ./dtls_client/dtls_pqc_client 127.0.0.1 4444 > logs/real_client.log 2>&1
CLIENT_EXIT=$?

echo ""
echo "[Step 5] Handshake Results:"
echo "         ─────────────────────────────────────────────────────"

if [ $CLIENT_EXIT -eq 0 ]; then
    echo "         ✓ CLIENT COMPLETED SUCCESSFULLY"
else
    echo "         ! CLIENT EXIT CODE: $CLIENT_EXIT"
fi

echo ""
echo "         SERVER OUTPUT:"
tail -30 logs/real_server.log | sed 's/^/         /'

echo ""
echo "         CLIENT OUTPUT:"
tail -30 logs/real_client.log | sed 's/^/         /'

echo "         ─────────────────────────────────────────────────────"
echo ""

# Stop server
echo "[Step 6] Stopping server..."
kill $SERVER_PID 2>/dev/null
sleep 1
echo "         ✓ Server stopped"
echo ""

# Wait for tcpdump
sleep 2
sudo pkill -f "tcpdump.*real_handshake" 2>/dev/null
sleep 1

# Analyze capture
echo "[Step 7] Analyzing captured traffic..."
if [ -f captures/real_handshake.pcap ]; then
    FILESIZE=$(stat -c%s captures/real_handshake.pcap 2>/dev/null || echo "0")
    PACKETS=$(tcpdump -r captures/real_handshake.pcap 2>/dev/null | wc -l)
    echo "         ✓ Capture file: captures/real_handshake.pcap"
    echo "           Size: $FILESIZE bytes"
    echo "           Packets: $PACKETS"
    
    if [ $PACKETS -gt 0 ]; then
        echo ""
        echo "         PACKET SUMMARY:"
        tcpdump -r captures/real_handshake.pcap -n 2>/dev/null | head -20 | sed 's/^/         /'
    fi
else
    echo "         ✗ No capture file created"
fi
echo ""

echo "════════════════════════════════════════════════════════════════"
echo "  SUMMARY"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Check for handshake completion
if grep -q "SSL_connect" logs/real_client.log 2>/dev/null; then
    echo "✓ Client initiated SSL_connect"
else
    echo "✗ Client did not initiate connection"
fi

if grep -q "Handshake complete" logs/real_server.log 2>/dev/null || \
   grep -q "accept" logs/real_server.log 2>/dev/null; then
    echo "✓ Server accepted connection"
else
    echo "✗ Server did not complete handshake"
fi

if grep -q "successfully" logs/real_client.log 2>/dev/null || \
   grep -q "Connected" logs/real_client.log 2>/dev/null; then
    echo "✓ Handshake completed successfully!"
else
    echo "✗ Handshake did not complete"
fi

echo ""
echo "Log files:"
echo "  • logs/real_server.log - Server output"
echo "  • logs/real_client.log - Client output"
echo "  • captures/real_handshake.pcap - Network capture"
echo ""
echo "════════════════════════════════════════════════════════════════"
