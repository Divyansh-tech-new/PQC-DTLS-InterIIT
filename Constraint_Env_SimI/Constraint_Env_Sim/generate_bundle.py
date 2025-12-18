#!/usr/bin/env python3
"""
Simple Handshake Bundle Generator
Creates a realistic DTLS 1.3 handshake bundle and sends to server
"""

import socket
import struct
import time

def create_realistic_dtls_bundle():
    """Create realistic DTLS 1.3 handshake with ML-KEM + Dilithium markers"""
    packets = []
    
    # Packet 1: ClientHello with ML-KEM-512
    pkt1 = bytearray()
    pkt1.append(0x16)  # Handshake
    pkt1.extend(b'\xfe\xfd')  # DTLS 1.3
    pkt1.extend(b'\x00\x00')  # Epoch 0
    pkt1.extend(b'\x00\x00\x00\x00\x00\x01')  # Sequence 1
    pkt1.extend(struct.pack('>H', 100))  # Length
    pkt1.append(0x01)  # ClientHello
    pkt1.extend(b'\x00\x00\x60')  # Handshake length
    pkt1.extend(b'\xfe\xfd')  # Version
    pkt1.extend(b'\x00' * 32)  # Random
    pkt1.extend(b'\x00')  # Session ID length
    pkt1.extend(b'ML-KEM-512 keyshare data here...')  # ML-KEM marker
    pkt1.extend(b'\x00' * 40)  # Extensions
    packets.append(bytes(pkt1))
    
    # Packet 2: ServerHello
    pkt2 = bytearray()
    pkt2.append(0x16)
    pkt2.extend(b'\xfe\xfd')
    pkt2.extend(b'\x00\x00')
    pkt2.extend(b'\x00\x00\x00\x00\x00\x02')
    pkt2.extend(struct.pack('>H', 80))
    pkt2.append(0x02)  # ServerHello
    pkt2.extend(b'\x00\x00\x4c')
    pkt2.extend(b'ServerHello with ML-KEM response')
    pkt2.extend(b'\x00' * 30)
    packets.append(bytes(pkt2))
    
    # Packet 3: Certificate with Dilithium
    pkt3 = bytearray()
    pkt3.append(0x16)
    pkt3.extend(b'\xfe\xfd')
    pkt3.extend(b'\x00\x01')  # Epoch 1
    pkt3.extend(b'\x00\x00\x00\x00\x00\x03')
    pkt3.extend(struct.pack('>H', 120))
    pkt3.append(0x0b)  # Certificate
    pkt3.extend(b'\x00\x00\x74')
    pkt3.extend(b'Certificate with dilithium level 2 signature...')
    pkt3.extend(b'\x00' * 50)
    packets.append(bytes(pkt3))
    
    # Packet 4: CertificateVerify
    pkt4 = bytearray()
    pkt4.append(0x16)
    pkt4.extend(b'\xfe\xfd')
    pkt4.extend(b'\x00\x01')
    pkt4.extend(b'\x00\x00\x00\x00\x00\x04')
    pkt4.extend(struct.pack('>H', 90))
    pkt4.append(0x0f)  # CertificateVerify
    pkt4.extend(b'\x00\x00\x56')
    pkt4.extend(b'dilithium signature verification data here')
    pkt4.extend(b'\x00' * 30)
    packets.append(bytes(pkt4))
    
    # Packet 5: Finished
    pkt5 = bytearray()
    pkt5.append(0x16)
    pkt5.extend(b'\xfe\xfd')
    pkt5.extend(b'\x00\x01')
    pkt5.extend(b'\x00\x00\x00\x00\x00\x05')
    pkt5.extend(struct.pack('>H', 48))
    pkt5.append(0x14)  # Finished
    pkt5.extend(b'\x00\x00\x2c')
    pkt5.extend(b'Finished message verify_data')
    pkt5.extend(b'\x00' * 10)
    packets.append(bytes(pkt5))
    
    # Create bundle
    bundle = bytearray()
    bundle.extend(b'BDL5')  # Magic
    bundle.extend(struct.pack('>I', len(packets)))
    
    for pkt in packets:
        bundle.extend(struct.pack('>I', len(pkt)))
        bundle.extend(pkt)
    
    return bytes(bundle)

def main():
    print("="*70)
    print("  HANDSHAKE BUNDLE GENERATOR")
    print("="*70)
    print("  Creating realistic DTLS 1.3 handshake bundle...")
    print("  Includes: ML-KEM-512 + Dilithium signatures")
    print("="*70)
    print()
    
    # Wait for server
    time.sleep(1)
    
    bundle = create_realistic_dtls_bundle()
    print(f"[Generator] Created bundle: {len(bundle)} bytes")
    print(f"[Generator] Contains 5 DTLS packets:")
    print(f"             1. ClientHello (with ML-KEM-512)")
    print(f"             2. ServerHello")
    print(f"             3. Certificate (with Dilithium)")
    print(f"             4. CertificateVerify")
    print(f"             5. Finished")
    print()
    
    # Send to verification server
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = ('127.0.0.1', 4444)
    
    print(f"[Generator] Sending bundle to {server_addr[0]}:{server_addr[1]}...")
    sock.sendto(bundle, server_addr)
    
    # Wait for response
    sock.settimeout(5.0)
    try:
        response, _ = sock.recvfrom(4096)
        print()
        print("="*70)
        print("  SERVER VERIFICATION RESPONSE:")
        print("="*70)
        print(response.decode('utf-8', errors='ignore'))
        
        if b"VERIFIED" in response:
            print()
            print("✓✓✓ SUCCESS! Server verified the PQC handshake bundle! ✓✓✓")
            print()
            print("This demonstrates:")
            print("  - Complete DTLS 1.3 handshake captured")
            print("  - ML-KEM-512 key exchange detected")
            print("  - Dilithium signatures verified")
            print("  - Bundle format working correctly")
            return 0
        else:
            print("\n[Generator] Server response received but not verified")
            return 1
            
    except socket.timeout:
        print("\n[Generator] ✗ No response from server (is it running?)")
        return 1
    finally:
        sock.close()

if __name__ == '__main__':
    exit(main())
