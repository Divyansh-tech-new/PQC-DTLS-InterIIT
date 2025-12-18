#!/usr/bin/env python3
"""
Simple packet reassembly checker - no external dependencies
Analyzes bridge log to show TCP→UDP reassembly status
"""

import sys
import re
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

def analyze_bridge_log(log_file):
    """Analyze bridge log for TCP→UDP reassembly"""
    print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
    print(f"{Colors.HEADER}BRIDGE LOG PACKET REASSEMBLY ANALYSIS{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
    print(f"Log file: {log_file}\n")
    
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"{Colors.FAIL}✗ Bridge log not found: {log_file}{Colors.ENDC}")
        return
    
    tcp_buffer = bytearray()
    packet_count = 0
    fragments = []
    tcp_recv_count = 0
    udp_sent_count = 0
    
    sequences_seen = []
    fragmented_packets = []
    complete_packets = []
    
    print(f"{Colors.OKBLUE}Reading bridge log...{Colors.ENDC}\n")
    
    for line_num, line in enumerate(lines, 1):
        # Track TCP receives (data coming from LiteX simulation)
        match_recv = re.search(r'TCP recv (\d+) bytes?: ([0-9a-fA-F]+)', line)
        if match_recv:
            size = int(match_recv.group(1))
            hex_data = match_recv.group(2)
            try:
                data = bytes.fromhex(hex_data)
                tcp_buffer.extend(data)
                fragments.append(size)
                tcp_recv_count += 1
            except ValueError:
                pass
        
        # Track UDP sends (reassembled packets sent to server)
        match_sent = re.search(r'TCP->UDP: sent (\d+) bytes', line)
        if match_sent:
            bytes_sent = int(match_sent.group(1))
            packet_count += 1
            udp_sent_count += 1
            
            print(f"{Colors.BOLD}{Colors.OKGREEN}━━━ UDP Packet #{packet_count} ━━━{Colors.ENDC}")
            print(f"  {Colors.OKCYAN}Line: {line_num}{Colors.ENDC}")
            print(f"  {Colors.OKCYAN}Size: {bytes_sent} bytes{Colors.ENDC}")
            print(f"  {Colors.OKCYAN}Assembled from {len(fragments)} TCP fragment(s){Colors.ENDC}")
            
            if fragments:
                frag_str = ', '.join([f"{f}B" for f in fragments])
                print(f"  Fragment sizes: [{frag_str}]")
            
            if len(tcp_buffer) >= bytes_sent:
                packet_data = tcp_buffer[:bytes_sent]
                tcp_buffer = tcp_buffer[bytes_sent:]
                
                # Show hex preview
                preview = packet_data[:min(32, len(packet_data))].hex()
                print(f"  Preview: {preview}{'...' if len(packet_data) > 32 else ''}")
                
                # Parse DTLS
                dtls = parse_dtls_record(packet_data)
                if dtls:
                    print(f"\n  {Colors.OKCYAN}╔═══ DTLS Record ═══{Colors.ENDC}")
                    print(f"  {Colors.OKCYAN}║{Colors.ENDC} Type: {get_content_type_name(dtls['content_type'])}")
                    print(f"  {Colors.OKCYAN}║{Colors.ENDC} Version: 0x{dtls['version']:04x}")
                    print(f"  {Colors.OKCYAN}║{Colors.ENDC} Epoch: {dtls['epoch']}")
                    print(f"  {Colors.OKCYAN}║{Colors.ENDC} Sequence: {dtls['sequence']}")
                    print(f"  {Colors.OKCYAN}║{Colors.ENDC} Payload Length: {dtls['length']} bytes")
                    print(f"  {Colors.OKCYAN}║{Colors.ENDC} Expected Total: {dtls['total_size']} bytes")
                    print(f"  {Colors.OKCYAN}║{Colors.ENDC} Actual Size: {len(packet_data)} bytes")
                    print(f"  {Colors.OKCYAN}╚{'═'*30}{Colors.ENDC}")
                    
                    sequences_seen.append(dtls['sequence'])
                    
                    # Check reassembly status
                    if len(packet_data) == dtls['total_size']:
                        print(f"\n  {Colors.OKGREEN}✓ STATUS: COMPLETE REASSEMBLY{Colors.ENDC}")
                        print(f"  {Colors.OKGREEN}  All {bytes_sent} bytes properly reassembled!{Colors.ENDC}")
                        complete_packets.append(packet_count)
                    elif len(packet_data) < dtls['total_size']:
                        missing = dtls['total_size'] - len(packet_data)
                        print(f"\n  {Colors.FAIL}✗ STATUS: FRAGMENTED / INCOMPLETE{Colors.ENDC}")
                        print(f"  {Colors.FAIL}  Missing {missing} bytes!{Colors.ENDC}")
                        fragmented_packets.append(packet_count)
                    else:
                        extra = len(packet_data) - dtls['total_size']
                        print(f"\n  {Colors.WARNING}! STATUS: MULTIPLE RECORDS OR PADDING{Colors.ENDC}")
                        print(f"  {Colors.WARNING}  {extra} extra bytes present{Colors.ENDC}")
                        
                        # Try to find next record
                        remaining = packet_data[dtls['total_size']:]
                        if len(remaining) >= 13:
                            dtls2 = parse_dtls_record(remaining)
                            if dtls2:
                                print(f"  {Colors.OKCYAN}  └─ Found 2nd Record: {get_content_type_name(dtls2['content_type'])} "
                                      f"(Seq={dtls2['sequence']}){Colors.ENDC}")
                                sequences_seen.append(dtls2['sequence'])
                        complete_packets.append(packet_count)
                else:
                    print(f"\n  {Colors.WARNING}! Not a valid DTLS record header{Colors.ENDC}")
                    print(f"  {Colors.WARNING}  (Could be encrypted or corrupted data){Colors.ENDC}")
            else:
                print(f"\n  {Colors.FAIL}✗ BUFFER UNDERRUN!{Colors.ENDC}")
                print(f"  {Colors.FAIL}  Need: {bytes_sent} bytes{Colors.ENDC}")
                print(f"  {Colors.FAIL}  Have: {len(tcp_buffer)} bytes{Colors.ENDC}")
                fragmented_packets.append(packet_count)
            
            fragments = []
            print()
    
    # Summary
    print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
    print(f"{Colors.HEADER}SUMMARY{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
    
    print(f"{Colors.OKBLUE}TCP Receives:{Colors.ENDC} {tcp_recv_count} fragments")
    print(f"{Colors.OKBLUE}UDP Sends:{Colors.ENDC} {udp_sent_count} packets\n")
    
    print(f"{Colors.OKGREEN}Complete packets:{Colors.ENDC} {len(complete_packets)}/{packet_count}")
    if complete_packets:
        print(f"  Packet numbers: {complete_packets}")
    
    if fragmented_packets:
        print(f"\n{Colors.FAIL}Fragmented/Incomplete packets:{Colors.ENDC} {len(fragmented_packets)}/{packet_count}")
        print(f"  Packet numbers: {fragmented_packets}")
    
    if tcp_buffer:
        print(f"\n{Colors.WARNING}Remaining in buffer:{Colors.ENDC} {len(tcp_buffer)} bytes (not yet sent)")
    else:
        print(f"\n{Colors.OKGREEN}Buffer empty:{Colors.ENDC} All data properly reassembled and sent")
    
    # Sequence analysis
    if sequences_seen:
        print(f"\n{Colors.OKCYAN}DTLS Sequences detected:{Colors.ENDC} {sorted(sequences_seen)}")
        
        # Check for gaps
        sequences_seen.sort()
        gaps = []
        for i in range(len(sequences_seen) - 1):
            if sequences_seen[i+1] - sequences_seen[i] > 1:
                gaps.append((sequences_seen[i], sequences_seen[i+1]))
        
        if gaps:
            print(f"{Colors.WARNING}  Sequence gaps found:{Colors.ENDC} {gaps}")
        else:
            print(f"{Colors.OKGREEN}  ✓ No sequence gaps{Colors.ENDC}")
        
        # Check for duplicates
        if len(sequences_seen) != len(set(sequences_seen)):
            dups = [x for x in sequences_seen if sequences_seen.count(x) > 1]
            print(f"{Colors.WARNING}  Duplicate sequences:{Colors.ENDC} {set(dups)}")
        else:
            print(f"{Colors.OKGREEN}  ✓ No duplicate sequences{Colors.ENDC}")
    
    # Final verdict
    print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
    if fragmented_packets:
        print(f"{Colors.FAIL}⚠ REASSEMBLY ISSUES DETECTED{Colors.ENDC}")
        print(f"{Colors.FAIL}Some packets were not properly reassembled.{Colors.ENDC}")
    elif packet_count == 0:
        print(f"{Colors.WARNING}⚠ NO PACKETS FOUND{Colors.ENDC}")
        print(f"{Colors.WARNING}Check if the bridge log contains packet data.{Colors.ENDC}")
    else:
        print(f"{Colors.OKGREEN}✓ ALL PACKETS PROPERLY REASSEMBLED!{Colors.ENDC}")
        print(f"{Colors.OKGREEN}All {packet_count} UDP packets were correctly assembled from TCP fragments.{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <bridge_log_file>")
        print(f"\nExample:")
        print(f"  {sys.argv[0]} logs/bridge.log")
        print(f"  {sys.argv[0]} logs/uart_bridge.log")
        sys.exit(1)
    
    log_file = sys.argv[1]
    analyze_bridge_log(log_file)
