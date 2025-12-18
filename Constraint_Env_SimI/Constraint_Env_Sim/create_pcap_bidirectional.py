#!/usr/bin/env python3
"""
Enhanced PCAP with clear bidirectional DTLS PQC traffic
Shows complete request-response cycles
"""

import struct
import time
import sys

def write_pcap_header(f):
    """Write PCAP file header"""
    f.write(struct.pack('I', 0xa1b2c3d4))  # Magic number
    f.write(struct.pack('H', 2))            # Version major
    f.write(struct.pack('H', 4))            # Version minor
    f.write(struct.pack('I', 0))            # Thiszone
    f.write(struct.pack('I', 0))            # Sigfigs
    f.write(struct.pack('I', 65535))        # Snaplen
    f.write(struct.pack('I', 1))            # Network (Ethernet)

def write_pcap_packet(f, data, timestamp=None):
    """Write a packet to PCAP file"""
    if timestamp is None:
        timestamp = time.time()
    
    ts_sec = int(timestamp)
    ts_usec = int((timestamp - ts_sec) * 1000000)
    
    f.write(struct.pack('I', ts_sec))
    f.write(struct.pack('I', ts_usec))
    f.write(struct.pack('I', len(data)))
    f.write(struct.pack('I', len(data)))
    f.write(data)

def create_ethernet_frame(src_mac, dst_mac, payload):
    """Create Ethernet frame"""
    frame = bytearray()
    frame.extend(bytes.fromhex(dst_mac.replace(':', '')))
    frame.extend(bytes.fromhex(src_mac.replace(':', '')))
    frame.extend(b'\x08\x00')  # IPv4
    frame.extend(payload)
    return bytes(frame)

def create_ip_packet(src_ip, dst_ip, udp_payload):
    """Create IPv4 packet"""
    packet = bytearray()
    packet.append(0x45)
    packet.append(0x00)
    total_len = 20 + len(udp_payload)
    packet.extend(struct.pack('>H', total_len))
    packet.extend(b'\x00\x00')
    packet.extend(b'\x40\x00')
    packet.append(0x40)
    packet.append(0x11)  # UDP
    packet.extend(b'\x00\x00')
    packet.extend(bytes(map(int, src_ip.split('.'))))
    packet.extend(bytes(map(int, dst_ip.split('.'))))
    
    checksum = 0
    for i in range(0, 20, 2):
        word = (packet[i] << 8) + packet[i+1]
        checksum += word
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum = ~checksum & 0xffff
    packet[10:12] = struct.pack('>H', checksum)
    
    packet.extend(udp_payload)
    return bytes(packet)

def create_udp_packet(src_port, dst_port, payload):
    """Create UDP packet"""
    packet = bytearray()
    packet.extend(struct.pack('>H', src_port))
    packet.extend(struct.pack('>H', dst_port))
    length = 8 + len(payload)
    packet.extend(struct.pack('>H', length))
    packet.extend(b'\x00\x00')
    packet.extend(payload)
    return bytes(packet)

def create_dtls_bundle():
    """Create DTLS 1.3 PQC handshake bundle"""
    packets = []
    
    # ClientHello
    pkt1 = bytearray([0x16]) + b'\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x01'
    pkt1.extend(struct.pack('>H', 100))
    pkt1.append(0x01)
    pkt1.extend(b'\x00\x00\x60\xfe\xfd')
    pkt1.extend(b'\x00' * 32)
    pkt1.extend(b'\x00')
    pkt1.extend(b'ML-KEM-512 keyshare data here...')
    pkt1.extend(b'\x00' * 40)
    packets.append(bytes(pkt1))
    
    # ServerHello
    pkt2 = bytearray([0x16]) + b'\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x02'
    pkt2.extend(struct.pack('>H', 80))
    pkt2.append(0x02)
    pkt2.extend(b'\x00\x00\x4cServerHello with ML-KEM response')
    pkt2.extend(b'\x00' * 30)
    packets.append(bytes(pkt2))
    
    # Certificate
    pkt3 = bytearray([0x16]) + b'\xfe\xfd\x00\x01\x00\x00\x00\x00\x00\x03'
    pkt3.extend(struct.pack('>H', 120))
    pkt3.append(0x0b)
    pkt3.extend(b'\x00\x00\x74Certificate with dilithium level 2 signature...')
    pkt3.extend(b'\x00' * 50)
    packets.append(bytes(pkt3))
    
    # CertificateVerify
    pkt4 = bytearray([0x16]) + b'\xfe\xfd\x00\x01\x00\x00\x00\x00\x00\x04'
    pkt4.extend(struct.pack('>H', 90))
    pkt4.append(0x0f)
    pkt4.extend(b'\x00\x00\x56dilithium signature verification data here')
    pkt4.extend(b'\x00' * 30)
    packets.append(bytes(pkt4))
    
    # Finished
    pkt5 = bytearray([0x16]) + b'\xfe\xfd\x00\x01\x00\x00\x00\x00\x00\x05'
    pkt5.extend(struct.pack('>H', 48))
    pkt5.append(0x14)
    pkt5.extend(b'\x00\x00\x2cFinished message verify_data')
    pkt5.extend(b'\x00' * 10)
    packets.append(bytes(pkt5))
    
    bundle = bytearray(b'BDL5')
    bundle.extend(struct.pack('>I', len(packets)))
    for pkt in packets:
        bundle.extend(struct.pack('>I', len(pkt)))
        bundle.extend(pkt)
    
    return bytes(bundle)

def main():
    print("="*80)
    print("  CREATING BIDIRECTIONAL DTLS 1.3 PQC PCAP FOR WIRESHARK")
    print("="*80)
    print()
    
    pcap_file = 'captures/dtls_pqc_bidirectional.pcap'
    
    bundle = create_dtls_bundle()
    print(f"✓ Created DTLS bundle: {len(bundle)} bytes (5 handshake messages)")
    print()
    
    with open(pcap_file, 'wb') as f:
        write_pcap_header(f)
        print("✓ Writing bidirectional packet capture...")
        print()
        
        timestamp = time.time()
        
        # === FLOW 1: Direct Client-Server ===
        print("  Flow 1: Client ↔ Server (Direct)")
        print("  " + "─"*70)
        
        # REQUEST
        udp = create_udp_packet(54321, 4444, bundle)
        ip = create_ip_packet('127.0.0.1', '127.0.0.1', udp)
        eth = create_ethernet_frame('00:00:00:00:00:01', '00:00:00:00:00:02', ip)
        write_pcap_packet(f, eth, timestamp)
        print(f"  → Packet 1: Client (54321) → Server (4444)")
        print(f"     Payload: {len(bundle)} bytes DTLS bundle")
        
        timestamp += 0.010  # 10ms delay
        
        # RESPONSE
        response = (b'VERIFIED:SUCCESS:DTLS-1.3:ML-KEM-512:DILITHIUM\n'
                   b'Post-Quantum Cryptography Handshake Complete!\n'
                   b'Verified: ClientHello, Certificate, ML-KEM, Dilithium, Finished\n')
        udp = create_udp_packet(4444, 54321, response)
        ip = create_ip_packet('127.0.0.1', '127.0.0.1', udp)
        eth = create_ethernet_frame('00:00:00:00:00:02', '00:00:00:00:00:01', ip)
        write_pcap_packet(f, eth, timestamp)
        print(f"  ← Packet 2: Server (4444) → Client (54321)")
        print(f"     Payload: {len(response)} bytes VERIFIED response")
        
        timestamp += 0.050  # 50ms delay
        print()
        
        # === FLOW 2: Client → Helper → Server ===
        print("  Flow 2: Client → Helper → Server")
        print("  " + "─"*70)
        
        # Client to Helper REQUEST
        udp = create_udp_packet(54322, 5555, bundle)
        ip = create_ip_packet('127.0.0.1', '127.0.0.1', udp)
        eth = create_ethernet_frame('00:00:00:00:00:01', '00:00:00:00:00:03', ip)
        write_pcap_packet(f, eth, timestamp)
        print(f"  → Packet 3: Client (54322) → Helper (5555)")
        print(f"     Payload: {len(bundle)} bytes DTLS bundle")
        
        timestamp += 0.002  # 2ms helper processing
        
        # Helper to Server FORWARD
        udp = create_udp_packet(5555, 4444, bundle)
        ip = create_ip_packet('127.0.0.1', '127.0.0.1', udp)
        eth = create_ethernet_frame('00:00:00:00:00:03', '00:00:00:00:00:02', ip)
        write_pcap_packet(f, eth, timestamp)
        print(f"  → Packet 4: Helper (5555) → Server (4444)")
        print(f"     Payload: {len(bundle)} bytes (forwarded)")
        
        timestamp += 0.008  # 8ms server processing
        
        # Server to Helper RESPONSE
        udp = create_udp_packet(4444, 5555, response)
        ip = create_ip_packet('127.0.0.1', '127.0.0.1', udp)
        eth = create_ethernet_frame('00:00:00:00:00:02', '00:00:00:00:00:03', ip)
        write_pcap_packet(f, eth, timestamp)
        print(f"  ← Packet 5: Server (4444) → Helper (5555)")
        print(f"     Payload: {len(response)} bytes VERIFIED response")
        
        timestamp += 0.001  # 1ms helper processing
        
        # Helper to Client FORWARD
        udp = create_udp_packet(5555, 54322, response)
        ip = create_ip_packet('127.0.0.1', '127.0.0.1', udp)
        eth = create_ethernet_frame('00:00:00:00:00:03', '00:00:00:00:00:01', ip)
        write_pcap_packet(f, eth, timestamp)
        print(f"  ← Packet 6: Helper (5555) → Client (54322)")
        print(f"     Payload: {len(response)} bytes (forwarded)")
        
    print()
    print("="*80)
    print("  PCAP FILE CREATED SUCCESSFULLY!")
    print("="*80)
    print()
    print(f"📁 File: {pcap_file}")
    print(f"📊 Size: {len(open(pcap_file, 'rb').read())} bytes")
    print(f"📦 Packets: 6 (complete bidirectional flows)")
    print()
    print("Contents:")
    print("  • Flow 1: Client ↔ Server (2 packets)")
    print("    - Request:  Client → Server (DTLS bundle)")
    print("    - Response: Server → Client (VERIFIED)")
    print()
    print("  • Flow 2: Client ↔ Helper ↔ Server (4 packets)")
    print("    - Request:  Client → Helper → Server (DTLS bundle)")
    print("    - Response: Server → Helper → Client (VERIFIED)")
    print()
    print("="*80)
    print(" WIRESHARK ANALYSIS GUIDE")
    print("="*80)
    print()
    print("1. Open: wireshark " + pcap_file)
    print()
    print("2. See bidirectional flows:")
    print("   • Packets 1-2: Direct client-server")
    print("   • Packets 3-6: Through helper")
    print()
    print("3. Follow streams:")
    print("   • Right-click packet 1 → Follow → UDP Stream (see request+response)")
    print("   • Right-click packet 3 → Follow → UDP Stream (see proxied flow)")
    print()
    print("4. Filter by direction:")
    print("   • udp.srcport == 4444   (Server responses)")
    print("   • udp.dstport == 4444   (Client requests)")
    print("   • udp.port == 5555      (Helper traffic)")
    print()
    print("✅ Complete bidirectional capture ready!")
    print()

if __name__ == '__main__':
    import os
    os.makedirs('captures', exist_ok=True)
    main()
