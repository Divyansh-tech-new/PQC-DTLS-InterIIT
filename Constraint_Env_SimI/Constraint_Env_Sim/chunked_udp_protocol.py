#!/usr/bin/env python3
"""
Chunked UDP Transmission Protocol
==================================

PROBLEM: Large DTLS packets need to be split into multiple UDP datagrams
SOLUTION: Custom framing protocol with reassembly support

Frame Format (Header: 16 bytes)
-------------------------------
[0-3]:   Magic (0xCDAB1234)       - Protocol identifier
[4-7]:   Message ID                - Unique message identifier
[8-9]:   Chunk ID (uint16)         - Current chunk number (0-indexed)
[10-11]: Total Chunks (uint16)     - Total number of chunks
[12-13]: Chunk Length (uint16)     - Length of payload in this chunk
[14-15]: CRC16                     - Checksum of payload
[16+]:   Payload                   - Actual data

Each UDP datagram = 16-byte header + payload (max 1400 bytes for safety)
"""

import struct
import socket
import time
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

# Protocol constants
MAGIC = 0xCDAB1234
HEADER_SIZE = 16
MAX_CHUNK_SIZE = 1400  # Safe UDP payload size (below MTU)


def calculate_crc16(data: bytes) -> int:
    """Calculate CRC16 checksum"""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


class ChunkedMessage:
    """Represents a message being reassembled from chunks"""
    def __init__(self, msg_id: int, total_chunks: int):
        self.msg_id = msg_id
        self.total_chunks = total_chunks
        self.chunks: Dict[int, bytes] = {}
        self.created_at = time.time()
        
    def add_chunk(self, chunk_id: int, data: bytes) -> bool:
        """Add a chunk. Returns True if message is complete."""
        if chunk_id >= self.total_chunks:
            raise ValueError(f"Invalid chunk_id {chunk_id} for message with {self.total_chunks} chunks")
        
        self.chunks[chunk_id] = data
        return len(self.chunks) == self.total_chunks
    
    def is_complete(self) -> bool:
        """Check if all chunks received"""
        return len(self.chunks) == self.total_chunks
    
    def reassemble(self) -> bytes:
        """Reassemble chunks into original message"""
        if not self.is_complete():
            raise RuntimeError(f"Message {self.msg_id} incomplete: {len(self.chunks)}/{self.total_chunks}")
        
        # Reassemble in order
        result = bytearray()
        for i in range(self.total_chunks):
            if i not in self.chunks:
                raise RuntimeError(f"Missing chunk {i}")
            result.extend(self.chunks[i])
        
        return bytes(result)
    
    def get_missing_chunks(self) -> List[int]:
        """Get list of missing chunk IDs"""
        return [i for i in range(self.total_chunks) if i not in self.chunks]


class ChunkedSender:
    """Sends large messages as chunked UDP datagrams"""
    
    def __init__(self, sock: socket.socket, remote_addr: Tuple[str, int]):
        self.sock = sock
        self.remote_addr = remote_addr
        self.next_msg_id = 0
        
    def send_message(self, data: bytes, verbose: bool = True) -> int:
        """
        Split data into chunks and send via UDP.
        Returns: message_id
        """
        if not data:
            raise ValueError("Cannot send empty message")
        
        msg_id = self.next_msg_id
        self.next_msg_id = (self.next_msg_id + 1) & 0xFFFFFFFF
        
        # Calculate chunks needed
        total_chunks = (len(data) + MAX_CHUNK_SIZE - 1) // MAX_CHUNK_SIZE
        
        if verbose:
            print(f"[SENDER] Msg {msg_id}: {len(data)} bytes → {total_chunks} chunks")
        
        # Send each chunk
        for chunk_id in range(total_chunks):
            start = chunk_id * MAX_CHUNK_SIZE
            end = min(start + MAX_CHUNK_SIZE, len(data))
            chunk_data = data[start:end]
            
            # Build header
            crc = calculate_crc16(chunk_data)
            header = struct.pack(
                '>IIHHHH',
                MAGIC,
                msg_id,
                chunk_id,
                total_chunks,
                len(chunk_data),
                crc
            )
            
            # Send datagram
            datagram = header + chunk_data
            self.sock.sendto(datagram, self.remote_addr)
            
            if verbose:
                print(f"  [CHUNK {chunk_id}/{total_chunks-1}] {len(chunk_data)} bytes, CRC=0x{crc:04x}")
        
        return msg_id


class ChunkedReceiver:
    """Receives and reassembles chunked UDP datagrams"""
    
    def __init__(self, timeout: float = 5.0):
        self.messages: Dict[int, ChunkedMessage] = {}
        self.timeout = timeout
        self.stats = {
            'chunks_received': 0,
            'messages_completed': 0,
            'crc_errors': 0,
            'duplicates': 0
        }
        
    def process_datagram(self, data: bytes, verbose: bool = True) -> Optional[bytes]:
        """
        Process a received UDP datagram.
        Returns: Complete message if this chunk completed it, else None
        """
        if len(data) < HEADER_SIZE:
            if verbose:
                print(f"[RECEIVER] Invalid datagram: too short ({len(data)} bytes)")
            return None
        
        # Parse header
        header = data[:HEADER_SIZE]
        payload = data[HEADER_SIZE:]
        
        try:
            magic, msg_id, chunk_id, total_chunks, chunk_len, expected_crc = struct.unpack('>IIHHHH', header)
        except struct.error as e:
            if verbose:
                print(f"[RECEIVER] Failed to parse header: {e}")
            return None
        
        # Validate magic
        if magic != MAGIC:
            if verbose:
                print(f"[RECEIVER] Invalid magic: 0x{magic:08x} (expected 0x{MAGIC:08x})")
            return None
        
        # Validate length
        if len(payload) != chunk_len:
            if verbose:
                print(f"[RECEIVER] Length mismatch: got {len(payload)}, header says {chunk_len}")
            return None
        
        # Validate CRC
        actual_crc = calculate_crc16(payload)
        if actual_crc != expected_crc:
            if verbose:
                print(f"[RECEIVER] CRC error: got 0x{actual_crc:04x}, expected 0x{expected_crc:04x}")
            self.stats['crc_errors'] += 1
            return None
        
        self.stats['chunks_received'] += 1
        
        # Get or create message
        if msg_id not in self.messages:
            self.messages[msg_id] = ChunkedMessage(msg_id, total_chunks)
            if verbose:
                print(f"[RECEIVER] New message {msg_id}: expecting {total_chunks} chunks")
        
        msg = self.messages[msg_id]
        
        # Check for duplicate
        if chunk_id in msg.chunks:
            if verbose:
                print(f"[RECEIVER] Duplicate chunk {chunk_id} for message {msg_id}")
            self.stats['duplicates'] += 1
            return None
        
        # Add chunk
        try:
            is_complete = msg.add_chunk(chunk_id, payload)
            
            if verbose:
                print(f"[RECEIVER] Msg {msg_id} chunk {chunk_id}/{total_chunks-1}: {len(payload)} bytes")
                print(f"            Progress: {len(msg.chunks)}/{total_chunks} chunks received")
            
            # If complete, reassemble and return
            if is_complete:
                complete_msg = msg.reassemble()
                del self.messages[msg_id]
                self.stats['messages_completed'] += 1
                
                if verbose:
                    print(f"[RECEIVER] ✓ Message {msg_id} COMPLETE: {len(complete_msg)} bytes reassembled")
                
                return complete_msg
            else:
                if verbose:
                    missing = msg.get_missing_chunks()
                    print(f"            Still need chunks: {missing[:10]}{'...' if len(missing) > 10 else ''}")
                
        except (ValueError, RuntimeError) as e:
            if verbose:
                print(f"[RECEIVER] Error processing chunk: {e}")
            return None
        
        return None
    
    def cleanup_stale(self, verbose: bool = False):
        """Remove messages that haven't completed within timeout"""
        now = time.time()
        stale = [
            msg_id for msg_id, msg in self.messages.items()
            if now - msg.created_at > self.timeout
        ]
        
        for msg_id in stale:
            msg = self.messages[msg_id]
            if verbose:
                print(f"[RECEIVER] Timeout: dropping incomplete message {msg_id} "
                      f"({len(msg.chunks)}/{msg.total_chunks} chunks)")
            del self.messages[msg_id]
    
    def get_stats(self) -> dict:
        """Get receiver statistics"""
        return {
            **self.stats,
            'pending_messages': len(self.messages)
        }


def test_chunking():
    """Test the chunking protocol"""
    print("=" * 80)
    print("CHUNKED UDP PROTOCOL TEST")
    print("=" * 80)
    
    # Test data
    test_data = b"A" * 5000  # 5KB message requiring multiple chunks
    
    print(f"\nTest data: {len(test_data)} bytes")
    print(f"Max chunk size: {MAX_CHUNK_SIZE} bytes")
    print(f"Expected chunks: {(len(test_data) + MAX_CHUNK_SIZE - 1) // MAX_CHUNK_SIZE}\n")
    
    # Simulate sender
    class MockSocket:
        def __init__(self):
            self.datagrams = []
        
        def sendto(self, data, addr):
            self.datagrams.append((data, addr))
    
    mock_sock = MockSocket()
    sender = ChunkedSender(mock_sock, ("127.0.0.1", 4444))
    
    print("-" * 80)
    print("SENDER:")
    print("-" * 80)
    msg_id = sender.send_message(test_data)
    
    print(f"\n✓ Sent {len(mock_sock.datagrams)} datagrams\n")
    
    # Simulate receiver
    print("-" * 80)
    print("RECEIVER:")
    print("-" * 80)
    receiver = ChunkedReceiver()
    
    complete_msg = None
    for i, (datagram, _) in enumerate(mock_sock.datagrams):
        print(f"\nProcessing datagram #{i+1}:")
        result = receiver.process_datagram(datagram)
        if result:
            complete_msg = result
    
    print("\n" + "=" * 80)
    print("RESULTS:")
    print("=" * 80)
    
    if complete_msg == test_data:
        print("✓ SUCCESS: Message reassembled correctly!")
        print(f"  Original: {len(test_data)} bytes")
        print(f"  Reassembled: {len(complete_msg)} bytes")
    else:
        print("✗ FAILURE: Reassembly mismatch!")
    
    print(f"\nReceiver stats: {receiver.get_stats()}")


if __name__ == "__main__":
    test_chunking()
