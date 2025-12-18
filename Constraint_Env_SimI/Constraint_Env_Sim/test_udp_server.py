#!/usr/bin/env python3
"""
Simple UDP Echo Server for Testing UART-UDP Bridge
This allows us to test the complete pipeline without DTLS complications
"""

import socket
import sys

def main():
    HOST = '0.0.0.0'
    PORT = 4444
    
    print("=" * 80)
    print(f"  UDP Echo Server (Testing Bridge)")
    print("=" * 80)
    print(f"  Listening on: {HOST}:{PORT}")
    print(f"  Will echo back any received UDP packets")
    print("=" * 80)
    print()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    
    print(f"[Server] Ready and listening...")
    print()
    
    packet_count = 0
    
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            packet_count += 1
            
            print(f"[{packet_count}] Received {len(data)} bytes from {addr[0]}:{addr[1]}")
            print(f"     Data: {data[:100]}")  # Show first 100 bytes
            
            # Echo back
            sock.sendto(data, addr)
            print(f"     Echoed back {len(data)} bytes")
            print()
            
    except KeyboardInterrupt:
        print("\n[Server] Shutting down...")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
