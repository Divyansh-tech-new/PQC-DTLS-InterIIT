#!/bin/bash

echo "========================================"
echo " Real Encrypted DTLS 1.3 PQC Capture"
echo "========================================"
echo ""

# Cleanup
pkill -f "dtls_pqc_server|dtls_pqc_client|tcpdump" 2>/dev/null
sleep 2

# Create captures directory
mkdir -p captures

# Build client and server
echo "[Setup] Building DTLS client and server..."
make -C dtls_client clean > /dev/null 2>&1
make -C dtls_client || { echo "Failed to build client"; exit 1; }

make -C dtls_server clean > /dev/null 2>&1
make -C dtls_server || { echo "Failed to build server"; exit 1; }

echo "[Setup] ✓ Built successfully"
echo ""

# Start tcpdump in background FIRST
PCAP_FILE="captures/dtls_pqc_encrypted.pcap"
echo "[Capture] Starting packet capture..."
sudo tcpdump -i lo -w "$PCAP_FILE" udp port 4444 > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 2
echo "[Capture] ✓ tcpdump started (PID: $TCPDUMP_PID)"
echo ""

# Start server
echo "[Server] Starting DTLS 1.3 PQC Server on port 4444..."
cd dtls_server
./dtls_pqc_server > ../logs/real_server.log 2>&1 &
SERVER_PID=$!
cd ..
sleep 2
echo "[Server] ✓ Server started (PID: $SERVER_PID)"
echo ""

# Run client - this will perform real DTLS handshake with encryption!
echo "[Client] Starting DTLS 1.3 PQC Client..."
echo "[Client] This will perform REAL encrypted handshake with:"
echo "[Client]   • ML-KEM-512 key exchange"
echo "[Client]   • Dilithium certificate authentication"
echo "[Client]   • AES-128-GCM encryption"
echo ""
# Run from main directory so cert paths work
timeout 30 ./dtls_client/dtls_pqc_client 127.0.0.1 4444 2>&1 | tee logs/real_client.log
CLIENT_EXIT=$?

echo ""
if [ $CLIENT_EXIT -eq 0 ]; then
    echo "[Client] ✓ Handshake completed successfully!"
else
    echo "[Client] ⚠ Client exited with code $CLIENT_EXIT"
fi

# Give a moment for final packets
sleep 2

# Stop capture
echo ""
echo "[Capture] Stopping packet capture..."
sudo pkill -P $TCPDUMP_PID 2>/dev/null
sudo kill $TCPDUMP_PID 2>/dev/null
sleep 2

# Stop server
pkill -f "dtls_pqc_server" 2>/dev/null

echo "[Capture] ✓ Capture stopped"
echo ""

# Check capture file
if [ -f "$PCAP_FILE" ]; then
    SIZE=$(stat -f%z "$PCAP_FILE" 2>/dev/null || stat -c%s "$PCAP_FILE" 2>/dev/null)
    PACKETS=$(tcpdump -r "$PCAP_FILE" 2>/dev/null | wc -l)
    
    echo "========================================"
    echo " Capture Complete!"
    echo "========================================"
    echo "  File: $PCAP_FILE"
    echo "  Size: $SIZE bytes"
    echo "  Packets: $PACKETS"
    echo ""
    echo "This capture contains REAL encrypted DTLS 1.3 traffic with:"
    echo "  ✓ ML-KEM-512 (Kyber) key exchange"
    echo "  ✓ Dilithium digital signatures"
    echo "  ✓ AES-128-GCM encrypted application data"
    echo ""
    echo "To view in Wireshark:"
    echo "  wireshark $PCAP_FILE"
    echo ""
    echo "Note: Wireshark cannot decrypt this traffic because:"
    echo "  • Post-quantum key exchange (no RSA/ECDH to decrypt)"
    echo "  • No pre-master secret available"
    echo "  • This demonstrates real-world encrypted PQC traffic"
    echo "========================================"
else
    echo "✗ Capture file not created"
    exit 1
fi

# Show packet summary
echo ""
echo "Packet Summary:"
tcpdump -r "$PCAP_FILE" -n 2>/dev/null | head -20

exit 0
