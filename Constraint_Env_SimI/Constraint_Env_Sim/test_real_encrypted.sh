#!/bin/bash

echo "========================================="
echo " Manual DTLS 1.3 PQC Real Traffic Test"
echo "========================================="
echo ""

# Cleanup
pkill -f "dtls_pqc_server|dtls_pqc_client" 2>/dev/null
sleep 1

# Create directories
mkdir -p captures logs

# Start server in background
echo "[1] Starting DTLS 1.3 PQC Server..."
./dtls_server/dtls_pqc_server > logs/real_server.log 2>&1 &
SERVER_PID=$!
echo "    Server PID: $SERVER_PID"
sleep 3

# Start tcpdump
echo ""
echo "[2] Starting packet capture on loopback interface..."
echo "    Capturing UDP port 4444..."
sudo timeout 25 tcpdump -i lo -w captures/dtls_pqc_encrypted.pcap udp port 4444 > /dev/null 2>&1 &
TCPDUMP_PID=$!
echo "    tcpdump PID: $TCPDUMP_PID"
sleep 2

# Run client
echo ""
echo "[3] Running DTLS 1.3 PQC Client..."
echo "    This will perform REAL encrypted handshake!"
echo ""
timeout 15 ./dtls_client/dtls_pqc_client_simple 127.0.0.1 4444 2>&1 | tee logs/real_client.log
CLIENT_EXIT=${PIPESTATUS[0]}

echo ""
echo "[4] Waiting for capture to complete..."
sleep 3

# Stop everything
echo ""
echo "[5] Stopping server and capture..."
kill $SERVER_PID 2>/dev/null
sudo kill $TCPDUMP_PID 2>/dev/null
sleep 2

# Check results
echo ""
echo "========================================="
echo " Results"
echo "========================================="

if [ $CLIENT_EXIT -eq 0 ]; then
    echo "✓ Client handshake: SUCCESS"
else
    echo "✗ Client handshake: FAILED (exit code: $CLIENT_EXIT)"
fi

if [ -f "captures/dtls_pqc_encrypted.pcap" ]; then
    SIZE=$(stat -c%s captures/dtls_pqc_encrypted.pcap 2>/dev/null)
    if [ "$SIZE" -gt 100 ]; then
        PACKETS=$(tcpdump -r captures/dtls_pqc_encrypted.pcap 2>/dev/null | wc -l)
        echo "✓ Capture file: captures/dtls_pqc_encrypted.pcap"
        echo "  Size: $SIZE bytes"
        echo "  Packets: $PACKETS"
        echo ""
        echo "Packet summary:"
        tcpdump -r captures/dtls_pqc_encrypted.pcap -n 2>/dev/null | head -15
    else
        echo "✗ Capture file is empty or too small"
    fi
else
    echo "✗ Capture file not created"
fi

echo ""
echo "To view in Wireshark:"
echo "  wireshark captures/dtls_pqc_encrypted.pcap"
echo ""

exit 0
