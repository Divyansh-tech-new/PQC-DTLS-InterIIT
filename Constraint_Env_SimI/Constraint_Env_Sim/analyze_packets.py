import re
import sys
import struct

def parse_dtls_record(data):
    """
    Attempts to parse a DTLS record header from the beginning of data.
    Returns (content_type, version, epoch, sequence_number, length) if successful, else None.
    DTLS 1.3 Record Header:
    ContentType (1)
    Version (2)
    Epoch (2)
    SequenceNumber (6)
    Length (2)
    """
    if len(data) < 13:
        return None
    
    content_type = data[0]
    version = (data[1] << 8) | data[2]
    epoch = (data[3] << 8) | data[4]
    # Sequence number is 6 bytes. 
    # struct.unpack doesn't handle 6-byte integers directly easily without padding.
    # Manual unpacking:
    seq_num = 0
    for i in range(5, 11):
        seq_num = (seq_num << 8) | data[i]
        
    length = (data[11] << 8) | data[12]
    
    return content_type, version, epoch, seq_num, length

def get_content_type_name(ct):
    if ct == 20: return "ChangeCipherSpec"
    if ct == 21: return "Alert"
    if ct == 22: return "Handshake"
    if ct == 23: return "ApplicationData"
    if ct == 24: return "Heartbeat"
    return f"Unknown({ct})"

def analyze_bridge_log(filename):
    print(f"Analyzing {filename} for packet reassembly...")
    
    current_tcp_buffer = bytearray()
    
    with open(filename, 'r') as f:
        lines = f.readlines()
        
    packet_count = 0
    
    for line in lines:
        # 1. Accumulate bytes from LiteX (TCP recv)
        match_recv = re.search(r'TCP recv \d+ bytes: ([0-9a-fA-F]+)\.\.\.', line)
        if match_recv:
            hex_str = match_recv.group(1)
            try:
                # The log format shown in view_file seems to be single bytes per line often?
                # "TCP recv 1 bytes: 20..."
                # But sometimes "TCP recv 2 bytes: 696d..."
                # The regex captures the hex part.
                bytes_val = bytes.fromhex(hex_str)
                current_tcp_buffer.extend(bytes_val)
            except ValueError:
                pass
            continue

        # 2. Check for packet transmission boundaries (TCP->UDP sent)
        match_sent = re.search(r'TCP->UDP: sent (\d+) bytes', line)
        if match_sent:
            bytes_sent = int(match_sent.group(1))
            packet_count += 1
            
            # The buffer should ideally contain exactly what was sent + maybe some leftovers if the log is async?
            # Assuming the log "sent X bytes" refers to the X bytes immediately preceding it in the stream 
            # OR that the buffer accumulates and then flushes X bytes.
            # Based on typical bridge logic: read TCP, write to UDP.
            
            # Let's assume current_tcp_buffer holds the data ready to be sent.
            # We take the first bytes_sent bytes.
            
            if len(current_tcp_buffer) >= bytes_sent:
                packet_data = current_tcp_buffer[:bytes_sent]
                # Remove sent data from buffer
                current_tcp_buffer = current_tcp_buffer[bytes_sent:]
                
                print(f"\n[Packet #{packet_count}] Sent {len(packet_data)} bytes to UDP as single UDP datagram")
                
                # Preview data
                preview_len = min(64, len(packet_data))
                preview_data = packet_data[:preview_len]
                ascii_preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in preview_data)
                print(f"  Preview (Hex): {preview_data.hex()}...")
                print(f"  Preview (Txt): {ascii_preview}...")

                # Check for DTLS record at the start
                parsed = parse_dtls_record(packet_data)
                
                if parsed:
                    ct, ver, epoch, seq, length = parsed
                    print(f"  -> Header Found AT START: {get_content_type_name(ct)} (Len={length}, Seq={seq}, Epoch={epoch})")
                    
                    if len(packet_data) == 13 + length:
                         print("  -> STATUS: COMPLETE RECORD")
                    elif len(packet_data) < 13 + length:
                         print(f"  -> STATUS: FRAGMENTED (Got {len(packet_data)} bytes, Need {13+length} total)")
                    else:
                         print(f"  -> STATUS: MULTIPLE RECORDS OR PADDING (Got {len(packet_data)} bytes, Record is {13+length})")
                
                # Also scan for potential headers inside the packet (e.g. if mixed with text)
                found_inner = False
                for i in range(1, len(packet_data) - 13):
                    # Quick heuristic: ContentType 20-25, Version 0xFE?? or 0x03??
                    if packet_data[i] in [20, 21, 22, 23, 24] and packet_data[i+1] in [0xfe, 0x03]:
                         p_inner = parse_dtls_record(packet_data[i:])
                         if p_inner:
                             ct2, ver2, epoch2, seq2, len2 = p_inner
                             # Sanity check length
                             if len2 < 16384:
                                 print(f"  -> POTENTIAL HEADER FOUND at offset {i}: {get_content_type_name(ct2)} (Len={len2}, Seq={seq2})")
                                 found_inner = True
                
                if not parsed and not found_inner:
                    print("  -> No valid DTLS headers found. Likely pure text/garbage.")
                    
            else:
                print(f"\n[WARNING] Log says sent {bytes_sent} bytes, but we only tracked {len(current_tcp_buffer)} bytes in buffer!")
    
    print("\nAnalysis Complete.")

def analyze_server_log(filename):
    """Analyze server log for received UDP packets"""
    print(f"\nAnalyzing server log: {filename}")
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
        
        packet_count = 0
        for line in lines:
            if "UDP Recv" in line or "Received" in line:
                packet_count += 1
                print(f"  [Server] {line.strip()}")
        
        if packet_count == 0:
            print("  -> No UDP packets received by server")
        else:
            print(f"  -> Total packets received: {packet_count}")
    except FileNotFoundError:
        print(f"  -> Server log not found")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_packets.py <bridge_log_file> [server_log_file]")
        sys.exit(1)
    
    analyze_bridge_log(sys.argv[1])
    
    if len(sys.argv) > 2:
        analyze_server_log(sys.argv[2])
