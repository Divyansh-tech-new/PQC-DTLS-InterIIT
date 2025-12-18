#!/usr/bin/env python3
"""
End-to-End Test of Chunked Protocol
Demonstrates proper packet reassembly with chunks
"""

import socket
import time
import threading
from chunked_udp_protocol import ChunkedSender, ChunkedReceiver, HEADER_SIZE, MAX_CHUNK_SIZE


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def simulate_server(port, test_data):
    """Simulates a server receiving chunked messages"""
    print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
    print(f"{Colors.HEADER}SERVER SIDE - Receiving and Reassembling{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    print(f"{Colors.OKBLUE}[SERVER] Listening on port {port}{Colors.ENDC}\n")
    
    receiver = ChunkedReceiver()
    received_messages = []
    
    sock.settimeout(5.0)
    
    try:
        while len(received_messages) < len(test_data):
            try:
                data, addr = sock.recvfrom(2048)
                print(f"{Colors.OKCYAN}[SERVER] Received datagram from {addr}: {len(data)} bytes{Colors.ENDC}")
                
                # Check header
                if len(data) >= HEADER_SIZE:
                    import struct
                    magic, msg_id, chunk_id, total_chunks, chunk_len, crc = struct.unpack(
                        '>IIHHHH', data[:HEADER_SIZE]
                    )
                    print(f"         Header: MsgID={msg_id}, Chunk={chunk_id}/{total_chunks-1}, "
                          f"Len={chunk_len}, CRC=0x{crc:04x}")
                
                # Process
                complete_msg = receiver.process_datagram(data, verbose=False)
                
                if complete_msg:
                    print(f"\n{Colors.OKGREEN}[SERVER] ✓✓✓ COMPLETE MESSAGE REASSEMBLED ✓✓✓{Colors.ENDC}")
                    print(f"{Colors.OKGREEN}         Size: {len(complete_msg)} bytes{Colors.ENDC}\n")
                    received_messages.append(complete_msg)
                    
                    # Verify
                    expected = test_data[len(received_messages) - 1]
                    if complete_msg == expected:
                        print(f"{Colors.OKGREEN}         ✓ Content matches expected!{Colors.ENDC}\n")
                    else:
                        print(f"{Colors.FAIL}         ✗ Content mismatch!{Colors.ENDC}\n")
                
            except socket.timeout:
                print(f"{Colors.WARNING}[SERVER] Timeout waiting for data{Colors.ENDC}")
                break
    
    finally:
        sock.close()
    
    print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
    print(f"{Colors.HEADER}SERVER SUMMARY{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
    
    stats = receiver.get_stats()
    print(f"{Colors.OKBLUE}Messages expected: {len(test_data)}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}Messages received: {len(received_messages)}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}Total chunks received: {stats['chunks_received']}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}CRC errors: {stats['crc_errors']}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}Duplicates: {stats['duplicates']}{Colors.ENDC}\n")
    
    if len(received_messages) == len(test_data):
        print(f"{Colors.OKGREEN}✓✓✓ ALL MESSAGES SUCCESSFULLY REASSEMBLED! ✓✓✓{Colors.ENDC}\n")
        return True
    else:
        print(f"{Colors.FAIL}✗✗✗ SOME MESSAGES LOST OR INCOMPLETE ✗✗✗{Colors.ENDC}\n")
        return False


def simulate_client(port, test_data):
    """Simulates a client sending chunked messages"""
    time.sleep(0.5)  # Let server start
    
    print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
    print(f"{Colors.HEADER}CLIENT SIDE - Chunking and Sending{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender = ChunkedSender(sock, ("127.0.0.1", port))
    
    for i, data in enumerate(test_data):
        print(f"{Colors.OKCYAN}[CLIENT] Sending message #{i+1}: {len(data)} bytes{Colors.ENDC}")
        
        # Calculate expected chunks
        expected_chunks = (len(data) + MAX_CHUNK_SIZE - 1) // MAX_CHUNK_SIZE
        print(f"         Will be split into {expected_chunks} chunk(s)\n")
        
        msg_id = sender.send_message(data, verbose=False)
        
        # Count actual datagrams sent
        print(f"{Colors.OKGREEN}         ✓ Sent as message ID {msg_id}{Colors.ENDC}\n")
        
        time.sleep(0.1)  # Small delay between messages
    
    sock.close()
    
    print(f"{Colors.OKGREEN}[CLIENT] All messages sent!{Colors.ENDC}\n")


def main():
    print(f"\n{Colors.BOLD}{Colors.HEADER}")
    print("=" * 80)
    print(" CHUNKED UDP PROTOCOL - END-TO-END TEST")
    print("=" * 80)
    print(f"{Colors.ENDC}\n")
    
    # Test cases with different sizes
    test_data = [
        b"Small message (fits in one chunk)",  # < 1400 bytes
        b"A" * 3000,  # Needs 3 chunks
        b"B" * 5500,  # Needs 4 chunks
        b"C" * 10000, # Needs 8 chunks
    ]
    
    print(f"{Colors.OKBLUE}Test Plan:{Colors.ENDC}")
    for i, data in enumerate(test_data):
        chunks_needed = (len(data) + MAX_CHUNK_SIZE - 1) // MAX_CHUNK_SIZE
        print(f"  Message {i+1}: {len(data):5} bytes → {chunks_needed} chunk(s)")
    print()
    
    port = 9999
    
    # Start server in thread
    server_thread = threading.Thread(target=simulate_server, args=(port, test_data))
    server_thread.start()
    
    # Start client
    simulate_client(port, test_data)
    
    # Wait for server
    server_thread.join()
    
    print(f"{Colors.BOLD}{Colors.OKGREEN}")
    print("=" * 80)
    print(" TEST COMPLETE")
    print("=" * 80)
    print(f"{Colors.ENDC}\n")


if __name__ == "__main__":
    main()
