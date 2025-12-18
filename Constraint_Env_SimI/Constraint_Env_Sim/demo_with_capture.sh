#!/bin/bash
# Capture DTLS 1.3 PQC traffic with tcpdump for Wireshark analysis

echo "========================================================================"
echo "  DTLS 1.3 PQC PACKET CAPTURE DEMO"
echo "========================================================================"
echo "  Capturing traffic for Wireshark analysis"
echo "  File: dtls_pqc_capture.pcap"
echo "========================================================================"
echo ""

# Check if running as root or with sudo for packet capture
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  Note: Running without sudo - may not capture all packets"
    echo "   For best results, run: sudo ./demo_with_capture.sh"
    echo ""
    USE_SUDO=""
else
    USE_SUDO="sudo"
fi

# Cleanup
pkill -f "bundled_dtls|bundled_handshake|tcpdump" 2>/dev/null
sleep 1

mkdir -p logs captures

# Start packet capture on loopback
echo "📡 Starting packet capture..."
echo "   Interface: lo (loopback)"
echo "   Ports: 4444 (server), 5555 (helper)"
echo "   Output: captures/dtls_pqc_capture.pcap"
echo ""

$USE_SUDO tcpdump -i lo -w captures/dtls_pqc_capture.pcap \
    'udp and (port 4444 or port 5555)' > logs/tcpdump.log 2>&1 &
TCPDUMP_PID=$!
sleep 3
echo "✓ Packet capture started (PID: $TCPDUMP_PID)"
echo ""

# Build and start server
echo "🔧 Building and starting components..."
cd dtls_server
make -f Makefile.bundled clean > /dev/null 2>&1
make -f Makefile.bundled > /dev/null 2>&1
cd ..

./dtls_server/bundled_dtls_server > logs/capture_server.log 2>&1 &
SERVER_PID=$!
sleep 2

# Start helper
python3 bundled_handshake_helper.py > logs/capture_helper.log 2>&1 &
HELPER_PID=$!
sleep 2

echo "✓ Server and helper running"
echo ""

# Generate traffic
echo "========================================"
echo " Generating DTLS 1.3 PQC Traffic"
echo "========================================"
echo ""
echo "📦 Sending DTLS handshake bundle..."
echo "   Contains: ClientHello, ServerHello, Certificate,"
echo "             CertificateVerify, Finished"
echo "   PQC: ML-KEM-512 + Dilithium"
echo ""

python3 generate_bundle.py > logs/capture_traffic.log 2>&1

# Wait for packets to be captured
sleep 5

# Stop capture
echo ""
echo "📡 Stopping packet capture..."
$USE_SUDO kill $TCPDUMP_PID 2>/dev/null
sleep 1

# Cleanup processes
kill $SERVER_PID $HELPER_PID 2>/dev/null
pkill -f "bundled_dtls|bundled_handshake" 2>/dev/null

# Show capture info
echo ""
echo "========================================================================"
echo "  CAPTURE COMPLETE"
echo "========================================================================"
echo ""

if [ -f captures/dtls_pqc_capture.pcap ]; then
    FILESIZE=$(ls -lh captures/dtls_pqc_capture.pcap | awk '{print $5}')
    echo "✅ Packet capture saved!"
    echo ""
    echo "📁 File: captures/dtls_pqc_capture.pcap"
    echo "📊 Size: $FILESIZE"
    echo ""
    
    # Try to get packet count
    if command -v capinfos &> /dev/null; then
        echo "📈 Capture statistics:"
        capinfos captures/dtls_pqc_capture.pcap | grep -E "Number of packets|File size|Capture duration"
    elif command -v tcpdump &> /dev/null; then
        PACKET_COUNT=$($USE_SUDO tcpdump -r captures/dtls_pqc_capture.pcap 2>/dev/null | wc -l)
        echo "📈 Total packets captured: $PACKET_COUNT"
    fi
    
    echo ""
    echo "========================================"
    echo " How to Analyze with Wireshark"
    echo "========================================"
    echo ""
    echo "1. Open Wireshark:"
    echo "   wireshark captures/dtls_pqc_capture.pcap"
    echo ""
    echo "2. Apply filters:"
    echo "   • udp.port == 4444  (Server traffic)"
    echo "   • udp.port == 5555  (Helper traffic)"
    echo "   • udp                (All UDP traffic)"
    echo ""
    echo "3. Look for:"
    echo "   • Bundle packets with magic header 'BDL5'"
    echo "   • DTLS handshake messages (type 0x16)"
    echo "   • ClientHello, Certificate, Finished messages"
    echo "   • ML-KEM-512 and Dilithium markers in payload"
    echo ""
    echo "4. Follow UDP stream:"
    echo "   Right-click packet → Follow → UDP Stream"
    echo ""
    
    # Try to show quick preview
    if command -v tcpdump &> /dev/null; then
        echo "========================================"
        echo " Quick Preview (first 10 packets)"
        echo "========================================"
        echo ""
        $USE_SUDO tcpdump -r captures/dtls_pqc_capture.pcap -nn -c 10 2>/dev/null
        echo ""
    fi
    
else
    echo "❌ Failed to create capture file"
    echo "   Try running with: sudo ./demo_with_capture.sh"
fi

echo "========================================"
echo " Additional Information"
echo "========================================"
echo ""
echo "Traffic captured:"
echo "  • Client → Server (port 4444)"
echo "  • Client → Helper (port 5555)"
echo "  • Helper → Server (port 4444)"
echo ""
echo "Protocol details:"
echo "  • Transport: UDP"
echo "  • Application: DTLS 1.3 bundled handshake"
echo "  • Key Exchange: ML-KEM-512 (Post-Quantum)"
echo "  • Signatures: Dilithium Level 2 (Post-Quantum)"
echo ""
echo "Files generated:"
echo "  • captures/dtls_pqc_capture.pcap  (Wireshark capture)"
echo "  • logs/capture_server.log         (Server log)"
echo "  • logs/capture_helper.log          (Helper log)"
echo "  • logs/capture_traffic.log        (Traffic generator)"
echo "  • logs/tcpdump.log                (Capture log)"
echo ""

echo "✅ Demo complete!"
echo ""
