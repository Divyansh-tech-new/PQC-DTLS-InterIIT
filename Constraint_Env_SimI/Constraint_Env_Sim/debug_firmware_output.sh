#!/bin/bash
# Debug script to capture raw firmware output
set -e

echo "Starting simulation..."
export PYTHONPATH=$(find $PWD -maxdepth 1 -name "pythondata*" -type d | tr '\n' ':')litex:migen:$PYTHONPATH
timeout 180 python3 litex/litex/tools/litex_sim.py \
    --csr-json csr.json \
    --cpu-type=vexriscv \
    --cpu-variant=full \
    --integrated-main-ram-size=0x02000000 \
    --ram-init=boot.bin \
    --output-dir=build/sim_sp \
    --non-interactive \
    < /dev/null > logs/sim_debug.log 2>&1 &
SIM_PID=$!
echo "Simulation PID: $SIM_PID"

# Wait for port
sleep 8
echo "Connecting to UART on port 1234..."

# Capture output
timeout 5 python3 -c "
import socket
s = socket.socket()
s.connect(('127.0.0.1', 1234))
s.settimeout(5)
data = b''
try:
    while len(data) < 2000:
        chunk = s.recv(100)
        if not chunk:
            break
        data += chunk
except:
    pass
s.close()
print('=== FIRMWARE OUTPUT ===')
print(data.decode('utf-8', errors='replace'))
print('=== END (', len(data), 'bytes) ===')
" || true

# Cleanup
kill $SIM_PID 2>/dev/null || true
wait $SIM_PID 2>/dev/null || true
echo "Done"
