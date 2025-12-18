#!/usr/bin/env python3
"""
Simple test to send a fake bundled DTLS handshake to the server
Demonstrates the one-shot verification concept
"""

import socket
import struct

def create_fake_dtls_bundle():
    """Create a fake DTLS handshake bundle with all required messages"""
    
    # Fake DTLS packets (just for demonstration)
    packets = []
    
    # Packet 1: ClientHello with ML-KEM-512 support
    client_hello = bytearray()
    client_hello.append(0x16)  # Handshake
    client_hello.extend(b'\xfe\xfd')  # DTLS 1.3
    client_hello.extend(b'\x00\x00')  # Epoch
    client_hello.extend(b'\x00\x00\x00\x00\x00\x01')  # Sequence
    client_hello.extend(b'\x00\x50')  # Length
    client_hello.append(0x01)  # ClientHello type
    client_hello.extend(b'\x00\x00\x4c')  # Handshake length
    client_hello.extend(b'ML-KEM-512 support here!')  # Fake data with ML-KEM marker
    client_hello.extend(b'\x00' * 50)  # Padding
    packets.append(bytes(client_hello))
    
    # Packet 2: Certificate with Dilithium signature
    certificate = bytearray()
    certificate.append(0x16)  # Handshake
    certificate.extend(b'\xfe\xfd')  # DTLS 1.3
    certificate.extend(b'\x00\x00')  # Epoch
    certificate.extend(b'\x00\x00\x00\x00\x00\x02')  # Sequence
    certificate.extend(b'\x00\x40')  # Length
    certificate.append(0x0b)  # Certificate type
    certificate.extend(b'\x00\x00\x3c')  # Handshake length
    certificate.extend(b'dilithium signature data here!')  # Fake Dilithium marker
    certificate.extend(b'\x00' * 30)  # Padding
    packets.append(bytes(certificate))
    
    # Packet 3: Finished message
    finished = bytearray()
    finished.append(0x16)  # Handshake
    finished.extend(b'\xfe\xfd')  # DTLS 1.3
    finished.extend(b'\x00\x00')  # Epoch
    finished.extend(b'\x00\x00\x00\x00\x00\x03')  # Sequence
    finished.extend(b'\x00\x20')  # Length
    finished.append(0x14)  # Finished type
    finished.extend(b'\x00\x00\x1c')  # Handshake length
    finished.extend(b'verify_data_here')  # Fake verify data
    finished.extend(b'\x00' * 12)  # Padding
    packets.append(bytes(finished))
    
    # Create bundle
    bundle = bytearray()
    bundle.extend(b'BDL5')  # Magic
    bundle.extend(struct.pack('>I', len(packets)))  # Packet count
    
    for pkt in packets:
        bundle.extend(struct.pack('>I', len(pkt)))  # Packet length
        bundle.extend(pkt)  # Packet data
    
    return bytes(bundle)

def main():
    print("="*60)
    print("  BUNDLED DTLS HANDSHAKE TEST")
    print("="*60)
    print()
    
    # Create fake bundle
    bundle = create_fake_dtls_bundle()
    print(f"[Test] Created fake handshake bundle: {len(bundle)} bytes")
    print(f"[Test] Contains 3 DTLS packets")
    print()
    
    # Send to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = ('127.0.0.1', 4444)
    
    print(f"[Test] Sending bundle to {server_addr[0]}:{server_addr[1]}...")
    sock.sendto(bundle, server_addr)
    
    # Wait for response
    sock.settimeout(3.0)
    try:
        response, _ = sock.recvfrom(4096)
        print()
        print("="*60)
        print("  SERVER RESPONSE:")
        print("="*60)
        print(response.decode('utf-8', errors='ignore'))
        
        if b"VERIFIED" in response:
            print("✓✓✓ SUCCESS! Server verified the bundled handshake!")
        else:
            print("Server response received (verification logic may need adjustment)")
            
    except socket.timeout:
        print()
        print("[Test] ✗ No response from server (is it running?)")
    
    sock.close()

if __name__ == '__main__':
    main()
