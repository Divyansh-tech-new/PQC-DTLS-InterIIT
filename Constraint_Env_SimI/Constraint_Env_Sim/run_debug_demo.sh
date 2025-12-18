#!/bin/bash
# Wrapper to run demo with packet capture
# Requires sudo for tcpdump

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)"
  exit 1
fi

mkdir -p captures logs

# Cleanup old captures
rm -f captures/debug.pcap

echo "starting tcpdump on loopback (lo) for ports 4444 (DTLS) and 1234 (UART)..."
tcpdump -i lo -w captures/debug.pcap "port 4444 or port 1234" > logs/tcpdump.log 2>&1 &
TCPDUMP_PID=$!

echo "Tcpdump started (PID: $TCPDUMP_PID)."
sleep 2

# Run the original demo script as regular user if possible, but here we are root.
# We will just run it.
# Set PYTHONPATH to include local LiteX/LiteEth directories
# This fixes "ModuleNotFoundError" when running as root/sudo
export PYTHONPATH=$PYTHONPATH:$(pwd)/litex:$(pwd)/liteeth:$(pwd)/litedram:$(pwd)/migen:$(pwd)

echo "Starting run_demo.sh with PYTHONPATH=$PYTHONPATH..."
./run_demo.sh

echo "Stopping tcpdump..."
kill $TCPDUMP_PID
sleep 1

echo "Capture saved to captures/debug.pcap"
echo "You can view this file in Wireshark."
