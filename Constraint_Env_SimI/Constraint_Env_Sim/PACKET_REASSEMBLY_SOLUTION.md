# Packet Reassembly Analysis & Solution

## Problem Identified

### Current Issue
Your DTLS transmission over UDP is failing because:

1. **No Proper Framing Protocol**
   - Data comes from LiteX as individual bytes over TCP
   - Bridge tries to "guess" when to send UDP packets
   - No mechanism to tell if a UDP packet is complete or fragmented

2. **Server Cannot Reassemble**
   - Server receives UDP datagrams but has no way to know:
     - Is this a complete message?
     - Is this part 1 of 5 chunks?
     - Which message does this chunk belong to?
     - Are all chunks received?

3. **Mathematical/Logical Flaw**
   - Current approach: TCP bytes → Buffer → Send when "looks complete"
   - Missing: Chunk ID, Total Chunks, Message ID, Length, Checksum
   - Result: Server gets random byte sequences, cannot reassemble

## Solution: Chunked UDP Protocol

### Protocol Design

Each UDP datagram has a **16-byte header**:

```
Offset | Size | Field          | Description
-------|------|----------------|----------------------------------
0-3    | 4    | Magic          | 0xCDAB1234 (protocol identifier)
4-7    | 4    | Message ID     | Unique message identifier
8-9    | 2    | Chunk ID       | Current chunk number (0-indexed)
10-11  | 2    | Total Chunks   | Total number of chunks
12-13  | 2    | Chunk Length   | Payload size in this chunk
14-15  | 2    | CRC16          | Checksum of payload
16+    | Var  | Payload        | Actual data (max 1400 bytes)
```

### Why This Works

1. **Sender (Bridge)**:
   ```
   TCP bytes → Buffer → Extract complete DTLS record → 
   Split into chunks → Add header to each → Send via UDP
   ```

2. **Receiver (Server)**:
   ```
   Receive UDP datagram → Parse header → Validate CRC →
   Store chunk → Check if all chunks received → Reassemble
   ```

3. **Mathematically Correct**:
   - Each chunk is tagged with its position (chunk_id)
   - Total size is known (total_chunks)
   - Data integrity verified (CRC16)
   - Message correlation maintained (message_id)

## Test Results

The end-to-end test proves it works:

| Message Size | Chunks Needed | Status |
|--------------|---------------|---------|
| 33 bytes     | 1 chunk       | ✓ PASS |
| 3000 bytes   | 3 chunks      | ✓ PASS |
| 5500 bytes   | 4 chunks      | ✓ PASS |
| 10000 bytes  | 8 chunks      | ✓ PASS |

**Results**: 4/4 messages (16 chunks) successfully reassembled with 0 CRC errors

## Files Created

1. **chunked_udp_protocol.py**
   - Core protocol implementation
   - ChunkedSender class
   - ChunkedReceiver class
   - CRC16 calculation
   - Message reassembly logic

2. **uart_udp_bridge_chunked.py**
   - Updated bridge using chunked protocol
   - Extracts complete DTLS records from TCP stream
   - Chunks and sends with proper headers

3. **dtls_server_chunked_wrapper.py**
   - Wrapper for existing DTLS server
   - Receives chunked datagrams
   - Reassembles before forwarding to DTLS server
   - Chunks responses back to client

4. **test_chunked_e2e.py**
   - End-to-end demonstration
   - Proves reassembly works correctly

5. **check_reassembly_simple.py**
   - Diagnostic tool to analyze logs
   - Shows packet fragmentation issues

## Usage

### Start the chunked bridge:
```bash
python3 uart_udp_bridge_chunked.py \
    --tcp-host 127.0.0.1 \
    --tcp-port 1234 \
    --udp-local-ip 192.168.1.100 \
    --udp-remote-ip 192.168.1.100 \
    --udp-remote-port 5555
```

### Start the server wrapper:
```bash
python3 dtls_server_chunked_wrapper.py \
    --listen-port 5555 \
    --dtls-server 127.0.0.1:4444
```

### Start actual DTLS server:
```bash
cd dtls_server
./dtls_pqc_server --port 4444
```

## Key Advantages

1. **Reliable**: CRC16 detects corruption
2. **Ordered**: Chunk IDs ensure proper reassembly
3. **Flexible**: Handles any message size
4. **Debuggable**: Clear headers for analysis
5. **Stateful**: Tracks multiple concurrent messages
6. **Timeout handling**: Cleans up incomplete messages

## Verification

Run the test to verify:
```bash
python3 test_chunked_e2e.py
```

This will show you:
- Chunks being sent with proper headers
- Server receiving and tracking chunks
- Complete reassembly of all messages
- Statistics (CRC errors, duplicates, etc.)

The output clearly shows **Message ID**, **Chunk ID/Total**, **Length**, and **CRC** 
for each datagram, proving the protocol works correctly.
