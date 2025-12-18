#!/usr/bin/env python3
"""
Bundled DTLS Handshake Helper
Collects all DTLS handshake packets from client and sends as ONE bundle to server
Server can verify the complete handshake in one shot - no packet-by-packet complexity
"""

import socket
import struct
import sys
import time

def main():
    RISCV_PORT = 5555
    SERVER_IP = "127.0.0.1"
    SERVER_PORT = 4444
    
    print("="*70)
    print("  BUNDLED DTLS HANDSHAKE HELPER")
    print("="*70)
    print("  Strategy: Collect all handshake packets → Send as ONE bundle")
    print("  Listen:  0.0.0.0:{}".format(RISCV_PORT))
    print("  Forward: {}:{}".format(SERVER_IP, SERVER_PORT))
    print("="*70)
    print()
    
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.bind(('0.0.0.0', RISCV_PORT))
    listen_sock.settimeout(1.0)
    
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print("[Helper] Listening for RISC-V client...")
    
    riscv_addr = None
    handshake_packets = []
    handshake_complete = False
    start_time = None
    
    while True:
        try:
            data, addr = listen_sock.recvfrom(4096)
            
            if not riscv_addr:
                riscv_addr = addr
                start_time = time.time()
                print(f"\n[Helper] ✓ Client connected from {addr}")
            
            # Check if this is a DTLS packet (starts with 0x14-0x17)
            if len(data) >= 13:
                content_type = data[0]
                version = struct.unpack('>H', data[1:3])[0]
                
                # DTLS 1.3 content types
                content_names = {
                    0x14: "ChangeCipherSpec",
                    0x15: "Alert",
                    0x16: "Handshake",
                    0x17: "ApplicationData"
                }
                
                ctype_name = content_names.get(content_type, "Unknown")
                
                print(f"\n[Helper] ← Packet #{len(handshake_packets)+1}: {ctype_name} ({len(data)} bytes)")
                print(f"        Version: 0x{version:04x}, ContentType: 0x{content_type:02x}")
                
                # Store this packet
                handshake_packets.append(data)
                
                # Check if handshake is complete
                # DTLS handshake typically: ClientHello → ServerHello → Certificate → 
                # CertificateVerify → Finished → ApplicationData
                if content_type == 0x17:  # ApplicationData = handshake done
                    handshake_complete = True
                    elapsed = time.time() - start_time
                    
                    print(f"\n{'='*70}")
                    print(f"  HANDSHAKE COMPLETE! Collected {len(handshake_packets)} packets")
                    print(f"  Time: {elapsed:.2f}s | Total size: {sum(len(p) for p in handshake_packets)} bytes")
                    print(f"{'='*70}")
                    
                    # Bundle ALL packets into one
                    bundle = create_bundle(handshake_packets)
                    
                    print(f"\n[Helper] → Sending BUNDLED handshake to server...")
                    print(f"        Bundle size: {len(bundle)} bytes")
                    print(f"        Contains: {len(handshake_packets)} DTLS packets")
                    
                    # Send the bundle
                    server_sock.sendto(bundle, (SERVER_IP, SERVER_PORT))
                    
                    # Wait for server response
                    server_sock.settimeout(5.0)
                    try:
                        response, _ = server_sock.recvfrom(8192)
                        print(f"\n[Helper] ← Server response: {len(response)} bytes")
                        
                        # Check if it's a success message
                        if b"VERIFIED" in response or b"SUCCESS" in response:
                            print(f"\n{'='*70}")
                            print(f"  ✓✓✓ SERVER VERIFIED THE HANDSHAKE! ✓✓✓")
                            print(f"{'='*70}")
                            print(response.decode('utf-8', errors='ignore'))
                        else:
                            print(f"[Helper] Response: {response[:200]}")
                        
                        # Forward response to client
                        listen_sock.sendto(response, riscv_addr)
                        
                    except socket.timeout:
                        print(f"[Helper] ✗ Server timeout")
                    
                    # Reset for next handshake
                    handshake_packets = []
                    handshake_complete = False
                    start_time = None
                
        except socket.timeout:
            # Check if we have incomplete handshake
            if handshake_packets and start_time:
                elapsed = time.time() - start_time
                if elapsed > 10.0:  # 10 second timeout
                    print(f"\n[Helper] ⚠ Handshake timeout ({len(handshake_packets)} packets collected)")
                    handshake_packets = []
                    start_time = None
            continue
        except KeyboardInterrupt:
            print("\n[Helper] Shutting down...")
            break

def create_bundle(packets):
    """
    Bundle format:
    [4 bytes: magic 0xBDL5] [4 bytes: packet count] 
    [For each packet: 4 bytes length + packet data]
    """
    bundle = bytearray()
    
    # Magic header: "BDL5" (Bundled DTLS)
    bundle.extend(b'BDL5')
    
    # Number of packets
    bundle.extend(struct.pack('>I', len(packets)))
    
    # Each packet with length prefix
    for pkt in packets:
        bundle.extend(struct.pack('>I', len(pkt)))
        bundle.extend(pkt)
    
    return bytes(bundle)

if __name__ == '__main__':
    main()
