#!/usr/bin/env python3
"""
Simple UDP Helper for testing data flow
Bypasses DTLS to verify communication path works
"""

import socket
import sys

def main():
    RISCV_PORT = 5555
    SERVER_IP = "127.0.0.1"
    SERVER_PORT = 4444
    
    print("="*60)
    print("  Simple UDP Helper (No DTLS)")
    print("="*60)
    print(f"  Listen:  0.0.0.0:{RISCV_PORT}")
    print(f"  Forward: {SERVER_IP}:{SERVER_PORT}")
    print("="*60)
    print()
    
    # Create sockets
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.bind(('0.0.0.0', RISCV_PORT))
    
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[Helper] Listening on UDP port {RISCV_PORT}...")
    
    riscv_addr = None
    
    while True:
        # Receive from RISC-V
        data, addr = listen_sock.recvfrom(2048)
        
        if not riscv_addr:
            riscv_addr = addr
            print(f"[Helper] ✓ RISC-V client connected from {addr}")
        
        print(f"\n[Helper] ← RISC-V: {len(data)} bytes")
        print(f"[Helper]   Hex:   {data[:64].hex()}")
        print(f"[Helper]   ASCII: {data[:64]}")
        
        # Forward to server
        print(f"[Helper] → Server: forwarding to {SERVER_IP}:{SERVER_PORT}")
        server_sock.sendto(data, (SERVER_IP, SERVER_PORT))
        
        # Wait for response
        server_sock.settimeout(2.0)
        try:
            response, _ = server_sock.recvfrom(2048)
            print(f"[Helper] ← Server: {len(response)} bytes")
            print(f"[Helper]   Response: {response[:64]}")
            
            # Forward back to RISC-V
            listen_sock.sendto(response, riscv_addr)
            print(f"[Helper] → RISC-V: forwarded response")
        except socket.timeout:
            print(f"[Helper] ✗ No response from server (timeout)")

if __name__ == '__main__':
    main()
