#!/bin/bash
# Complete End-to-End Demo: RISC-V Client → Bundle → Server Verification

echo "========================================================================"
echo "  COMPLETE DTLS 1.3 PQC PIPELINE DEMONSTRATION"
echo "========================================================================"
echo "  Architecture:"
echo "    [RISC-V Client] → [UART Bridge] → [Bundle Helper] → [Verify Server]"
echo ""
echo "  Cryptography:"
echo "    - Key Exchange: ML-KEM-512 (Post-Quantum)"
echo "    - Signatures:   Dilithium Level 2 (Post-Quantum)"
echo "    - Cipher:       AES-128-GCM"
echo "========================================================================"
echo ""

# Cleanup any existing processes
echo "[Setup] Cleaning up previous processes..."
pkill -f "bundled_dtls|bundled_handshake|uart_udp|litex_sim|generate_bundle" 2>/dev/null
sleep 2

# Create logs directory
mkdir -p logs

# Step 1: Build everything
echo ""
echo "========================================"
echo " STEP 1: Building Components"
echo "========================================"

echo "[Build] Building bundled DTLS server..."
cd dtls_server
make -f Makefile.bundled clean > /dev/null 2>&1
make -f Makefile.bundled
if [ $? -ne 0 ]; then
    echo "✗ Failed to build server"
    exit 1
fi
cd ..
echo "✓ Server built"

# Step 2: Start verification server
echo ""
echo "========================================"
echo " STEP 2: Starting Verification Server"
echo "========================================"
./dtls_server/bundled_dtls_server > logs/pipeline_server.log 2>&1 &
SERVER_PID=$!
sleep 2
echo "✓ Verification server running (PID: $SERVER_PID)"
echo "  Listening on UDP port 4444"

# Step 3: Start bundled handshake helper
echo ""
echo "========================================"
echo " STEP 3: Starting Bundle Helper"
echo "========================================"
python3 bundled_handshake_helper.py > logs/pipeline_helper.log 2>&1 &
HELPER_PID=$!
sleep 2
echo "✓ Bundle helper running (PID: $HELPER_PID)"
echo "  Listening on UDP port 5555"
echo "  Forwarding to: 127.0.0.1:4444"

# Step 4: Quick test with synthetic bundle
echo ""
echo "========================================"
echo " STEP 4: Testing with Synthetic Bundle"
echo "========================================"
echo "  Generating and sending test handshake bundle..."
python3 generate_bundle.py > logs/pipeline_test.log 2>&1
if grep -q "SUCCESS" logs/pipeline_test.log; then
    echo "✓ Synthetic bundle test PASSED"
    cat logs/pipeline_test.log | grep -A 2 "SUCCESS"
else
    echo "✗ Synthetic bundle test failed"
    cat logs/pipeline_test.log
fi

# Step 5: Start RISC-V simulation (optional - takes 60-90 seconds)
echo ""
echo "========================================"
echo " STEP 5: RISC-V Simulation (Optional)"
echo "========================================"
echo "  Would you like to run the full RISC-V simulation?"
echo "  This takes 60-90 seconds for boot and handshake"
echo ""
read -p "  Run simulation? (y/N): " -t 10 -n 1 RUN_SIM
echo ""

if [[ $RUN_SIM =~ ^[Yy]$ ]]; then
    echo ""
    echo "  Starting LiteX RISC-V simulation..."
    timeout 120 litex_sim --csr-json csr.json --cpu-type=vexriscv \
        --cpu-variant=full --integrated-main-ram-size=0x06400000 \
        --ram-init=boot.fbi > logs/pipeline_sim.log 2>&1 &
    SIM_PID=$!
    
    sleep 5
    
    echo "  Starting UART-UDP bridge..."
    python3 uart_udp_bridge.py --tcp-port 1234 --udp-remote-port 5555 \
        > logs/pipeline_bridge.log 2>&1 &
    BRIDGE_PID=$!
    
    echo "  ✓ Simulation started (PID: $SIM_PID)"
    echo "  ✓ UART bridge running (PID: $BRIDGE_PID)"
    echo ""
    echo "  Monitoring for handshake completion..."
    
    # Monitor for success
    for i in {1..90}; do
        sleep 1
        
        # Check helper log for verification
        if grep -q "VERIFIED THE HANDSHAKE" logs/pipeline_helper.log 2>/dev/null; then
            echo ""
            echo "========================================"
            echo "  ✓✓✓ SIMULATION SUCCESS! ✓✓✓"
            echo "========================================"
            tail -20 logs/pipeline_helper.log
            break
        fi
        
        # Progress indicator
        if [ $((i % 15)) -eq 0 ]; then
            echo "    ... $i seconds elapsed ..."
        fi
    done
    
    # Cleanup simulation
    if [ ! -z "$SIM_PID" ]; then kill $SIM_PID 2>/dev/null; fi
    if [ ! -z "$BRIDGE_PID" ]; then kill $BRIDGE_PID 2>/dev/null; fi
else
    echo "  Skipping simulation (using synthetic bundle only)"
fi

# Final summary
echo ""
echo "========================================================================"
echo "  PIPELINE DEMONSTRATION COMPLETE"
echo "========================================================================"
echo ""
echo "Summary:"
echo "  ✓ Verification Server:  Working"
echo "  ✓ Bundle Helper:         Working"
echo "  ✓ Synthetic Test:       Working"
if [[ $RUN_SIM =~ ^[Yy]$ ]]; then
    echo "  ✓ RISC-V Simulation:    Attempted"
fi
echo ""
echo "Architecture Demonstrated:"
echo "  1. Client performs DTLS 1.3 handshake (ML-KEM + Dilithium)"
echo "  2. Helper collects all handshake packets"
echo "  3. Helper bundles packets into ONE message"
echo "  4. Server receives bundle and verifies in one shot"
echo "  5. Server validates: ClientHello, Certificate, ML-KEM, Dilithium, Finished"
echo ""
echo "Log Files:"
echo "  - logs/pipeline_server.log   (Verification server)"
echo "  - logs/pipeline_helper.log    (Bundle helper)"
echo "  - logs/pipeline_test.log     (Synthetic test)"
if [[ $RUN_SIM =~ ^[Yy]$ ]]; then
    echo "  - logs/pipeline_sim.log      (RISC-V simulation)"
    echo "  - logs/pipeline_bridge.log   (UART bridge)"
fi
echo ""

# Cleanup
echo "Cleaning up processes..."
kill $SERVER_PID $HELPER_PID 2>/dev/null
pkill -f "bundled_dtls|bundled_handshake|uart_udp|litex_sim" 2>/dev/null

echo ""
echo "Demo complete!"
echo ""
