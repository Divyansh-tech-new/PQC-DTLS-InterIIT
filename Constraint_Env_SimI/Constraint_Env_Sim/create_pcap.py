#!/usr/bin/env python3
"""
Create a PCAP file with DTLS 1.3 PQC handshake packets
This creates a Wireshark-readable capture file showing the bundled handshake
"""

import struct
import time

def write_pcap_header(f):
    """Write PCAP file header"""
    # Global header
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
    
    # Packet header
    f.write(struct.pack('I', ts_sec))       # Timestamp seconds
    f.write(struct.pack('I', ts_usec))      # Timestamp microseconds
    f.write(struct.pack('I', len(data)))    # Included length
    f.write(struct.pack('I', len(data)))    # Original length
    f.write(data)                            # Packet data

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
    
    # IP header
    packet.append(0x45)  # Version 4, IHL 5
    packet.append(0x00)  # DSCP, ECN
    total_len = 20 + len(udp_payload)
    packet.extend(struct.pack('>H', total_len))
    packet.extend(b'\x00\x00')  # Identification
    packet.extend(b'\x40\x00')  # Flags, Fragment offset
    packet.append(0x40)  # TTL
    packet.append(0x11)  # Protocol (UDP)
    packet.extend(b'\x00\x00')  # Checksum (will calculate)
    packet.extend(bytes(map(int, src_ip.split('.'))))
    packet.extend(bytes(map(int, dst_ip.split('.'))))
    
    # Calculate checksum
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
    packet.extend(b'\x00\x00')  # Checksum (optional for IPv4)
    packet.extend(payload)
    return bytes(packet)

def create_dtls_handshake_bundle():
    """Create DTLS 1.3 handshake bundle (same as generate_bundle.py)"""
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
    print("  CREATING DTLS 1.3 PQC PCAP FILE FOR WIRESHARK")
    print("="*70)
    print()
    
    pcap_file = 'captures/dtls_pqc_demo.pcap'
    
    print(f"Creating: {pcap_file}")
    print()
    
    # Create bundle
    bundle = create_dtls_handshake_bundle()
    print(f"✓ Created DTLS bundle: {len(bundle)} bytes")
    print(f"  Contains 5 handshake packets")
    print()
    
    # Create PCAP file
    with open(pcap_file, 'wb') as f:
        write_pcap_header(f)
        print("✓ Wrote PCAP header")
        
        timestamp = time.time()
        
        # Packet 1: Client → Server (direct)
        udp = create_udp_packet(54321, 4444, bundle)
        ip = create_ip_packet('127.0.0.1', '127.0.0.1', udp)
        eth = create_ethernet_frame('00:00:00:00:00:01', '00:00:00:00:00:02', ip)
        write_pcap_packet(f, eth, timestamp)
        print(f"✓ Packet 1: Client → Server (port 4444) - {len(bundle)} bytes bundle")
        
        timestamp += 0.001
        
        # Packet 2: Server → Client (response)
        response = b'VERIFIED:SUCCESS:DTLS-1.3:ML-KEM-512:DILITHIUM\n'
        udp = create_udp_packet(4444, 54321, response)
        ip = create_ip_packet('127.0.0.1', '127.0.0.1', udp)
        eth = create_ethernet_frame('00:00:00:00:00:02', '00:00:00:00:00:01', ip)
        write_pcap_packet(f, eth, timestamp)
        print(f"✓ Packet 2: Server → Client - VERIFIED response")
        
        timestamp += 0.001
        
        # Packet 3: Client → Helper
        udp = create_udp_packet(54322, 5555, bundle)
        ip = create_ip_packet('127.0.0.1', '127.0.0.1', udp)
        eth = create_ethernet_frame('00:00:00:00:00:01', '00:00:00:00:00:03', ip)
        write_pcap_packet(f, eth, timestamp)
        print(f"✓ Packet 3: Client → Helper (port 5555) - {len(bundle)} bytes bundle")
        
        timestamp += 0.001
        
        # Packet 4: Helper → Server (forwarded)
        udp = create_udp_packet(5555, 4444, bundle)
        ip = create_ip_packet('127.0.0.1', '127.0.0.1', udp)
        eth = create_ethernet_frame('00:00:00:00:00:03', '00:00:00:00:00:02', ip)
        write_pcap_packet(f, eth, timestamp)
        print(f"✓ Packet 4: Helper → Server (forwarded bundle)")
        
    print()
    print("="*70)
    print("  PCAP FILE CREATED SUCCESSFULLY!")
    print("="*70)
    print()
    print(f"File: {pcap_file}")
    print(f"Size: {len(open(pcap_file, 'rb').read())} bytes")
    print()
    print("Contents:")
    print("  • 4 UDP packets")
    print("  • DTLS 1.3 handshake bundle (489 bytes)")
    print("  • ML-KEM-512 key exchange markers")
    print("  • Dilithium signature markers")
    print("  • Server verification response")
    print()
    print("="*70)
    print(" HOW TO VIEW IN WIRESHARK")
    print("="*70)
    print()
    print("1. Open the capture:")
    print(f"   wireshark {pcap_file}")
    print()
    print("2. Filter by port:")
    print("   udp.port == 4444  (Server)")
    print("   udp.port == 5555  (Helper)")
    print()
    print("3. Inspect bundle:")
    print("   • Right-click → Follow → UDP Stream")
    print("   • Look for 'BDL5' magic header")
    print("   • Expand UDP payload to see DTLS packets")
    print()
    print("4. Search for PQC markers:")
    print("   • Edit → Find Packet → String: 'ML-KEM'")
    print("   • Edit → Find Packet → String: 'dilithium'")
    print()
    print("✅ Ready for analysis!")
    print()

if __name__ == '__main__':
    import os
    os.makedirs('captures', exist_ok=True)
    main()
