#!/usr/bin/env python3
"""
Comprehensive packet reassembly checker for DTLS traffic
Shows detailed information about packets sent, received, and reassembly status
"""

import sys
import re
from scapy.all import rdpcap, UDP, IP, Raw
from collections import defaultdict

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def parse_dtls_record(data):
    """Parse DTLS record header"""
    if len(data) < 13:
        return None
    
    content_type = data[0]
    version = (data[1] << 8) | data[2]
    epoch = (data[3] << 8) | data[4]
    
    seq_num = 0
    for i in range(5, 11):
        seq_num = (seq_num << 8) | data[i]
    
    length = (data[11] << 8) | data[12]
    
    return {
        'content_type': content_type,
        'version': version,
        'epoch': epoch,
        'sequence': seq_num,
        'length': length,
        'total_size': 13 + length
    }

def get_content_type_name(ct):
    types = {
        20: "ChangeCipherSpec",
        21: "Alert",
        22: "Handshake",
        23: "ApplicationData",
        24: "Heartbeat"
    }
    return types.get(ct, f"Unknown({ct})")

def analyze_pcap(pcap_file):
    """Analyze PCAP file for packet details"""
    print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
    print(f"{Colors.HEADER}PCAP Analysis: {pcap_file}{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
    
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"{Colors.FAIL}Error reading PCAP: {e}{Colors.ENDC}")
        return
    
    udp_packets = [pkt for pkt in packets if UDP in pkt]
    
    print(f"{Colors.OKBLUE}Total packets in PCAP: {len(packets)}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}UDP packets: {len(udp_packets)}{Colors.ENDC}\n")
    
    # Group by direction
    client_to_server = []
    server_to_client = []
    
    for pkt in udp_packets:
        if IP in pkt:
            # Assuming client is lower port or specific IP
            if pkt[UDP].sport < pkt[UDP].dport:
                client_to_server.append(pkt)
            else:
                server_to_client.append(pkt)
    
    print(f"{Colors.OKCYAN}Client → Server: {len(client_to_server)} packets{Colors.ENDC}")
    print(f"{Colors.OKCYAN}Server → Client: {len(server_to_client)} packets{Colors.ENDC}\n")
    
    # Analyze each direction
    analyze_direction(client_to_server, "CLIENT → SERVER")
    analyze_direction(server_to_client, "SERVER → CLIENT")
    
    # Check for reassembly issues
    check_reassembly(client_to_server, server_to_client)

def analyze_direction(packets, direction):
    """Analyze packets in one direction"""
    print(f"\n{Colors.BOLD}{Colors.UNDERLINE}{direction}{Colors.ENDC}")
    print(f"{'-'*80}\n")
    
    if not packets:
        print(f"{Colors.WARNING}No packets in this direction{Colors.ENDC}\n")
        return
    
    for idx, pkt in enumerate(packets, 1):
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            size = len(payload)
            
            print(f"{Colors.OKGREEN}[Packet {idx}]{Colors.ENDC} Size: {size} bytes")
            
            if IP in pkt:
                print(f"  IP: {pkt[IP].src}:{pkt[UDP].sport} → {pkt[IP].dst}:{pkt[UDP].dport}")
            
            # Try to parse DTLS record
            dtls = parse_dtls_record(payload)
            if dtls:
                print(f"  {Colors.OKCYAN}DTLS Record:{Colors.ENDC}")
                print(f"    Type: {get_content_type_name(dtls['content_type'])}")
                print(f"    Version: 0x{dtls['version']:04x}")
                print(f"    Epoch: {dtls['epoch']}")
                print(f"    Sequence: {dtls['sequence']}")
                print(f"    Payload Length: {dtls['length']} bytes")
                print(f"    Total Record Size: {dtls['total_size']} bytes")
                
                # Check reassembly status
                if size == dtls['total_size']:
                    print(f"    {Colors.OKGREEN}✓ Status: COMPLETE RECORD{Colors.ENDC}")
                elif size < dtls['total_size']:
                    print(f"    {Colors.FAIL}✗ Status: FRAGMENTED (Missing {dtls['total_size'] - size} bytes){Colors.ENDC}")
                else:
                    extra = size - dtls['total_size']
                    print(f"    {Colors.WARNING}! Status: MULTIPLE RECORDS/PADDING (+{extra} extra bytes){Colors.ENDC}")
                    
                    # Try to find next record
                    remaining = payload[dtls['total_size']:]
                    if len(remaining) >= 13:
                        dtls2 = parse_dtls_record(remaining)
                        if dtls2:
                            print(f"    {Colors.OKCYAN}Found 2nd Record: {get_content_type_name(dtls2['content_type'])}{Colors.ENDC}")
            else:
                print(f"  {Colors.WARNING}! Not a valid DTLS record (or encrypted){Colors.ENDC}")
                # Show hex preview
                preview = payload[:min(32, len(payload))].hex()
                print(f"  Preview: {preview}...")
            
            print()

def check_reassembly(client_pkts, server_pkts):
    """Check for reassembly issues"""
    print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
    print(f"{Colors.HEADER}REASSEMBLY ANALYSIS{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
    
    # Track sequences
    client_sequences = []
    server_sequences = []
    
    for pkt in client_pkts:
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            dtls = parse_dtls_record(payload)
            if dtls:
                client_sequences.append(dtls['sequence'])
    
    for pkt in server_pkts:
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            dtls = parse_dtls_record(payload)
            if dtls:
                server_sequences.append(dtls['sequence'])
    
    # Check for missing sequences
    print(f"{Colors.OKBLUE}Client Sequences: {sorted(client_sequences)}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}Server Sequences: {sorted(server_sequences)}{Colors.ENDC}\n")
    
    # Check gaps
    def check_gaps(sequences, name):
        if not sequences:
            return
        sequences = sorted(sequences)
        gaps = []
        for i in range(len(sequences) - 1):
            if sequences[i+1] - sequences[i] > 1:
                gaps.append((sequences[i], sequences[i+1]))
        
        if gaps:
            print(f"{Colors.WARNING}{name} has sequence gaps: {gaps}{Colors.ENDC}")
        else:
            print(f"{Colors.OKGREEN}{name} has no sequence gaps ✓{Colors.ENDC}")
    
    check_gaps(client_sequences, "Client")
    check_gaps(server_sequences, "Server")
    
    # Check for duplicates
    def check_duplicates(sequences, name):
        if len(sequences) != len(set(sequences)):
            dups = [x for x in sequences if sequences.count(x) > 1]
            print(f"{Colors.WARNING}{name} has duplicate sequences: {set(dups)}{Colors.ENDC}")
        else:
            print(f"{Colors.OKGREEN}{name} has no duplicate sequences ✓{Colors.ENDC}")
    
    check_duplicates(client_sequences, "Client")
    check_duplicates(server_sequences, "Server")

def analyze_bridge_log(log_file):
    """Analyze bridge log for TCP→UDP reassembly"""
    print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
    print(f"{Colors.HEADER}BRIDGE LOG Analysis: {log_file}{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
    
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"{Colors.FAIL}Bridge log not found{Colors.ENDC}")
        return
    
    tcp_buffer = bytearray()
    packet_count = 0
    fragments = []
    
    for line in lines:
        # Track TCP receives
        match_recv = re.search(r'TCP recv (\d+) bytes?: ([0-9a-fA-F]+)', line)
        if match_recv:
            size = int(match_recv.group(1))
            hex_data = match_recv.group(2)
            try:
                data = bytes.fromhex(hex_data)
                tcp_buffer.extend(data)
                fragments.append(size)
            except ValueError:
                pass
        
        # Track UDP sends
        match_sent = re.search(r'TCP->UDP: sent (\d+) bytes', line)
        if match_sent:
            bytes_sent = int(match_sent.group(1))
            packet_count += 1
            
            print(f"{Colors.OKGREEN}[UDP Packet {packet_count}]{Colors.ENDC}")
            print(f"  Size: {bytes_sent} bytes")
            print(f"  Assembled from {len(fragments)} TCP fragment(s): {fragments}")
            
            if len(tcp_buffer) >= bytes_sent:
                packet_data = tcp_buffer[:bytes_sent]
                tcp_buffer = tcp_buffer[bytes_sent:]
                
                # Parse DTLS
                dtls = parse_dtls_record(packet_data)
                if dtls:
                    print(f"  {Colors.OKCYAN}DTLS: {get_content_type_name(dtls['content_type'])} "
                          f"(Seq={dtls['sequence']}, Len={dtls['length']}){Colors.ENDC}")
                    
                    if len(packet_data) == dtls['total_size']:
                        print(f"  {Colors.OKGREEN}✓ Complete reassembly{Colors.ENDC}")
                    else:
                        print(f"  {Colors.WARNING}! Size mismatch: got {len(packet_data)}, "
                              f"expected {dtls['total_size']}{Colors.ENDC}")
                else:
                    print(f"  {Colors.WARNING}! Not a valid DTLS record{Colors.ENDC}")
            else:
                print(f"  {Colors.FAIL}✗ Buffer underrun: need {bytes_sent}, have {len(tcp_buffer)}{Colors.ENDC}")
            
            fragments = []
            print()
    
    print(f"\n{Colors.OKBLUE}Total UDP packets sent: {packet_count}{Colors.ENDC}")
    if tcp_buffer:
        print(f"{Colors.WARNING}Remaining buffer: {len(tcp_buffer)} bytes{Colors.ENDC}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file> [bridge_log]")
        print(f"\nExample:")
        print(f"  {sys.argv[0]} captures/dtls_pqc_capture.pcap logs/bridge.log")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    analyze_pcap(pcap_file)
    
    if len(sys.argv) > 2:
        bridge_log = sys.argv[2]
        analyze_bridge_log(bridge_log)
    
    print(f"\n{Colors.OKGREEN}{'='*80}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}Analysis Complete!{Colors.ENDC}")
    print(f"{Colors.OKGREEN}{'='*80}{Colors.ENDC}\n")
