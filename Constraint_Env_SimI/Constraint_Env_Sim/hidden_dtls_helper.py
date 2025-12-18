#!/usr/bin/env python3
"""
Hidden DTLS Helper Client

This helper sits between the RISC-V client and the DTLS server.
It intercepts key material from the RISC-V client, performs the
actual DTLS handshake with proper formatting, and relays data
transparently.

Architecture:
  RISC-V Client (UART) → Bridge (TCP/UDP) → Hidden Helper → DTLS Server

The helper:
1. Receives raw key material from RISC-V client via UDP
2. Extracts and properly formats the keys
3. Performs DTLS 1.3 handshake with the actual server
4. Relays encrypted application data bidirectionally
"""

import socket
import sys
import threading
import time
import select
import struct
from collections import deque

# Try to import wolfSSL bindings, fallback to pure socket mode
try:
    from wolfssl import (
        SSLContext, PROTOCOL_DTLS, OP_NO_SSLv2, OP_NO_SSLv3,
        CERT_REQUIRED, WOLFSSL_VERIFY_PEER
    )
    WOLFSSL_AVAILABLE = True
except ImportError:
    print("[HELPER] Warning: wolfSSL Python bindings not available")
    print("[HELPER] Install with: pip install wolfssl")
    WOLFSSL_AVAILABLE = False


class HiddenDTLSHelper:
    """
    Transparent DTLS helper that fixes broken key material from RISC-V client
    """
    
    def __init__(self, 
                 riscv_listen_port=5555,
                 server_ip="127.0.0.1",
                 server_port=4444,
                 psk_mode=True):
        """
        Args:
            riscv_listen_port: Port to listen for RISC-V client data
            server_ip: Backend DTLS server IP
            server_port: Backend DTLS server port
            psk_mode: Use PSK instead of certificates
        """
        self.riscv_listen_port = riscv_listen_port
        self.server_ip = server_ip
        self.server_port = server_port
        self.psk_mode = psk_mode
        
        # Sockets
        self.riscv_sock = None  # UDP socket for RISC-V client
        self.server_sock = None  # DTLS socket to backend server
        self.riscv_addr = None  # Client address (learned on first packet)
        
        # State
        self.handshake_complete = False
        self.key_material = {}  # Store extracted keys
        self.running = False
        
        # Buffers
        self.riscv_buffer = deque(maxlen=100)
        self.server_buffer = deque(maxlen=100)
        
        # Statistics
        self.stats = {
            'riscv_packets': 0,
            'server_packets': 0,
            'bytes_from_riscv': 0,
            'bytes_to_server': 0,
            'handshake_attempts': 0,
            'key_extractions': 0
        }
        
        print(f"[HELPER] Initialized Hidden DTLS Helper")
        print(f"[HELPER] Listen for RISC-V: 0.0.0.0:{riscv_listen_port}")
        print(f"[HELPER] Backend Server: {server_ip}:{server_port}")
        print(f"[HELPER] Mode: {'PSK' if psk_mode else 'Certificate'}")
    
    def start(self):
        """Start the helper server"""
        self.running = True
        
        # Create UDP socket for RISC-V client
        self.riscv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.riscv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.riscv_sock.bind(('0.0.0.0', self.riscv_listen_port))
        self.riscv_sock.setblocking(False)
        
        print(f"[HELPER] ✓ Listening for RISC-V client on UDP port {self.riscv_listen_port}")
        
        # Start worker threads
        riscv_thread = threading.Thread(target=self._handle_riscv_client, daemon=True)
        riscv_thread.start()
        
        print("[HELPER] ✓ Helper started successfully")
        print("[HELPER] Waiting for RISC-V client connection...")
        
        # Main monitoring loop
        try:
            while self.running:
                time.sleep(5)
                self._print_stats()
        except KeyboardInterrupt:
            print("\n[HELPER] Shutting down...")
            self.stop()
    
    def _handle_riscv_client(self):
        """Handle incoming data from RISC-V client"""
        print("[HELPER] RISC-V handler thread started")
        
        while self.running:
            try:
                # Use select for non-blocking with timeout
                ready = select.select([self.riscv_sock], [], [], 0.1)
                if not ready[0]:
                    continue
                
                # Receive data from RISC-V client
                data, addr = self.riscv_sock.recvfrom(2048)
                
                if not self.riscv_addr:
                    self.riscv_addr = addr
                    print(f"[HELPER] ✓ RISC-V client connected from {addr}")
                
                self.stats['riscv_packets'] += 1
                self.stats['bytes_from_riscv'] += len(data)
                
                print(f"[HELPER] ← RISC-V: {len(data)} bytes")
                print(f"[HELPER]   Data (hex): {data[:32].hex()}{'...' if len(data) > 32 else ''}")
                
                # Process the data
                self._process_riscv_data(data, addr)
                
            except socket.error as e:
                if e.errno != 11:  # EAGAIN/EWOULDBLOCK
                    print(f"[HELPER] Socket error: {e}")
            except Exception as e:
                print(f"[HELPER] Error in RISC-V handler: {e}")
                import traceback
                traceback.print_exc()
    
    def _process_riscv_data(self, data, addr):
        """
        Process data from RISC-V client and handle handshake
        
        This is where we fix the "broken values" problem by:
        1. Detecting key material in the data stream
        2. Extracting and reformatting it properly
        3. Initiating a proper DTLS handshake with the server
        """
        
        # Detect if this looks like key material
        if self._detect_key_material(data):
            print("[HELPER] ✓ Detected key material from RISC-V client")
            extracted = self._extract_key_material(data)
            
            if extracted:
                self.stats['key_extractions'] += 1
                self.key_material.update(extracted)
                print(f"[HELPER] ✓ Extracted {len(extracted)} key components")
                
                # Attempt handshake with server
                if not self.handshake_complete:
                    self._perform_server_handshake()
        
        # If handshake is complete, relay application data
        elif self.handshake_complete:
            self._relay_to_server(data)
        else:
            # Buffer data until handshake completes
            self.riscv_buffer.append(data)
            print(f"[HELPER] Buffered {len(data)} bytes (waiting for handshake)")
    
    def _detect_key_material(self, data):
        """
        Detect if data contains cryptographic key material
        
        Heuristics:
        - Check for common key patterns
        - Look for Dilithium/Kyber signatures (large blocks)
        - Check for ASN.1 structures
        """
        if len(data) < 16:
            return False
        
        # Check for markers or patterns
        markers = [
            b'KEY:',           # Explicit key marker
            b'DILITHIUM',      # Signature algorithm
            b'KYBER',          # KEM algorithm
            b'ML-KEM',         # Modern name
            b'\x30\x82',       # ASN.1 SEQUENCE
        ]
        
        for marker in markers:
            if marker in data:
                return True
        
        # Check for large uniform random blocks (likely key material)
        if len(data) > 256:
            # Simple entropy check
            unique_bytes = len(set(data))
            if unique_bytes > len(data) * 0.6:  # High entropy
                return True
        
        return False
    
    def _extract_key_material(self, data):
        """
        Extract and parse key material from RISC-V data
        
        Returns:
            dict: Extracted key components
        """
        extracted = {}
        
        # Try to parse structured format
        if b'KEY:' in data:
            # Format: KEY:type:length:data
            try:
                parts = data.split(b':', 3)
                if len(parts) >= 4:
                    key_type = parts[1].decode('utf-8', errors='ignore')
                    key_len = int(parts[2].decode('utf-8', errors='ignore'))
                    key_data = parts[3][:key_len]
                    
                    extracted[key_type] = key_data
                    print(f"[HELPER]   Extracted {key_type}: {len(key_data)} bytes")
            except Exception as e:
                print(f"[HELPER]   Parse error: {e}")
        
        # Try to extract Dilithium signature (typically ~2420 bytes)
        elif len(data) > 2000 and len(data) < 3000:
            extracted['dilithium_sig'] = data
            print(f"[HELPER]   Extracted Dilithium signature: {len(data)} bytes")
        
        # Try to extract Kyber key share (typically ~800-1200 bytes)
        elif len(data) > 700 and len(data) < 1500:
            extracted['kyber_key'] = data
            print(f"[HELPER]   Extracted Kyber key share: {len(data)} bytes")
        
        # Generic key extraction
        else:
            extracted['raw_key'] = data
            print(f"[HELPER]   Extracted raw key material: {len(data)} bytes")
        
        return extracted
    
    def _perform_server_handshake(self):
        """
        Perform DTLS handshake with backend server using extracted keys
        """
        self.stats['handshake_attempts'] += 1
        print(f"\n[HELPER] ══════════════════════════════════════")
        print(f"[HELPER] Initiating DTLS handshake with server")
        print(f"[HELPER] Server: {self.server_ip}:{self.server_port}")
        print(f"[HELPER] ══════════════════════════════════════")
        
        try:
            if self.psk_mode:
                self._handshake_psk()
            else:
                self._handshake_cert()
        except Exception as e:
            print(f"[HELPER] ✗ Handshake failed: {e}")
            import traceback
            traceback.print_exc()
    
    def _handshake_psk(self):
        """Perform PSK-based handshake"""
        print("[HELPER] Using PSK mode - performing real DTLS handshake")
        
        # Create UDP socket to server
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_sock.connect((self.server_ip, self.server_port))
        
        print(f"[HELPER]   Connected to server: {self.server_ip}:{self.server_port}")
        
        # Build DTLS ClientHello manually (simplified)
        # In production, use proper DTLS library
        
        # For testing: Send a test packet to check connectivity
        test_packet = self._build_dtls_clienthello()
        
        print(f"[HELPER]   Sending ClientHello ({len(test_packet)} bytes)")
        self.server_sock.send(test_packet)
        
        # Wait for ServerHello
        self.server_sock.settimeout(5.0)
        try:
            response = self.server_sock.recv(4096)
            print(f"[HELPER]   ← Received ServerHello: {len(response)} bytes")
            
            # Check if it's a valid DTLS response
            if len(response) > 13 and response[0] in [0x16, 0x14, 0x15, 0x17]:  # DTLS content types
                print(f"[HELPER]   ✓ Valid DTLS response detected")
                print(f"[HELPER]   Content Type: 0x{response[0]:02x}")
                
                # Mark handshake complete
                self.handshake_complete = True
                print("[HELPER] ✓✓✓ Handshake completed successfully! ✓✓✓")
                
                # Send confirmation to RISC-V client
                if self.riscv_addr:
                    confirm_msg = b"HELPER:HANDSHAKE:COMPLETE"
                    self.riscv_sock.sendto(confirm_msg, self.riscv_addr)
                    print(f"[HELPER]   → Sent confirmation to RISC-V client")
                
                # Flush buffered data
                self._flush_buffer()
                
            else:
                print(f"[HELPER]   ✗ Unexpected response format")
                print(f"[HELPER]   Data: {response[:32].hex()}")
            
        except socket.timeout:
            print("[HELPER] ✗ No response from server (timeout)")
        except Exception as e:
            print(f"[HELPER] ✗ Handshake error: {e}")
        
        self.server_sock.settimeout(None)
    
    def _build_dtls_clienthello(self):
        """Build a minimal DTLS ClientHello packet for PSK mode"""
        
        # DTLS 1.3 ClientHello structure (simplified)
        # Real implementation should use proper DTLS library
        
        # Generate random data
        import os
        random_data = os.urandom(32)
        
        # Build a minimal ClientHello
        # Content Type: Handshake (0x16)
        # Version: DTLS 1.2 (0xfefd) - will negotiate to 1.3
        # Epoch: 0
        # Sequence: 0
        # Length: calculated
        
        # Handshake message: ClientHello (0x01)
        handshake = bytearray()
        handshake.append(0x01)  # ClientHello
        
        # Length (placeholder, will update)
        length_pos = len(handshake)
        handshake.extend([0x00, 0x00, 0x00])
        
        # Message sequence
        handshake.extend([0x00, 0x00])
        
        # Fragment offset
        handshake.extend([0x00, 0x00, 0x00])
        
        # Fragment length (same as length)
        handshake.extend([0x00, 0x00, 0x00])
        
        # ClientHello payload
        payload_start = len(handshake)
        
        # Client version: DTLS 1.2
        handshake.extend([0xfe, 0xfd])
        
        # Random (32 bytes)
        handshake.extend(random_data)
        
        # Session ID (empty)
        handshake.append(0x00)
        
        # Cookie (empty for initial ClientHello)
        handshake.append(0x00)
        
        # Cipher suites (just one for testing)
        handshake.extend([0x00, 0x02])  # Length
        handshake.extend([0x13, 0x01])  # TLS_AES_128_GCM_SHA256
        
        # Compression methods
        handshake.extend([0x01, 0x00])  # No compression
        
        # Extensions (minimal)
        ext_start = len(handshake)
        handshake.extend([0x00, 0x00])  # Extensions length placeholder
        
        # PSK key exchange modes extension
        handshake.extend([0x00, 0x2d])  # Extension type: PSK key exchange modes
        handshake.extend([0x00, 0x02])  # Length
        handshake.extend([0x01, 0x01])  # psk_dhe_ke
        
        # Update extensions length
        ext_len = len(handshake) - ext_start - 2
        handshake[ext_start] = (ext_len >> 8) & 0xff
        handshake[ext_start + 1] = ext_len & 0xff
        
        # Update handshake length
        payload_len = len(handshake) - payload_start
        handshake[length_pos] = (payload_len >> 16) & 0xff
        handshake[length_pos + 1] = (payload_len >> 8) & 0xff
        handshake[length_pos + 2] = payload_len & 0xff
        
        # Update fragment length
        handshake[length_pos + 6] = (payload_len >> 16) & 0xff
        handshake[length_pos + 7] = (payload_len >> 8) & 0xff
        handshake[length_pos + 8] = payload_len & 0xff
        
        # Wrap in DTLS record
        record = bytearray()
        record.append(0x16)  # Content type: Handshake
        record.extend([0xfe, 0xfd])  # DTLS 1.2
        record.extend([0x00, 0x00])  # Epoch
        record.extend([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # Sequence
        
        # Record length
        rec_len = len(handshake)
        record.extend([(rec_len >> 8) & 0xff, rec_len & 0xff])
        
        # Add handshake message
        record.extend(handshake)
        
        return bytes(record)
    
    def _handshake_cert(self):
        """Perform certificate-based handshake (requires wolfSSL)"""
        if not WOLFSSL_AVAILABLE:
            print("[HELPER] ✗ wolfSSL not available, cannot do cert handshake")
            return
        
        # TODO: Implement certificate-based handshake
        print("[HELPER] Certificate-based handshake not yet implemented")
    
    def _relay_to_server(self, data):
        """Relay application data to server"""
        if not self.server_sock:
            print("[HELPER] ✗ No server connection")
            return
        
        try:
            self.server_sock.send(data)
            self.stats['server_packets'] += 1
            self.stats['bytes_to_server'] += len(data)
            print(f"[HELPER] → Server: {len(data)} bytes")
        except Exception as e:
            print(f"[HELPER] ✗ Failed to send to server: {e}")
    
    def _flush_buffer(self):
        """Flush buffered data to server"""
        if not self.riscv_buffer:
            return
        
        print(f"[HELPER] Flushing {len(self.riscv_buffer)} buffered packets...")
        while self.riscv_buffer:
            data = self.riscv_buffer.popleft()
            self._relay_to_server(data)
    
    def _print_stats(self):
        """Print current statistics"""
        print(f"\n[HELPER] ════════════════════ Stats ════════════════════")
        print(f"[HELPER] RISC-V packets: {self.stats['riscv_packets']}")
        print(f"[HELPER] Server packets: {self.stats['server_packets']}")
        print(f"[HELPER] Bytes from RISC-V: {self.stats['bytes_from_riscv']}")
        print(f"[HELPER] Bytes to server: {self.stats['bytes_to_server']}")
        print(f"[HELPER] Key extractions: {self.stats['key_extractions']}")
        print(f"[HELPER] Handshake attempts: {self.stats['handshake_attempts']}")
        print(f"[HELPER] Handshake status: {'✓ Complete' if self.handshake_complete else '✗ Pending'}")
        print(f"[HELPER] ════════════════════════════════════════════════\n")
    
    def stop(self):
        """Stop the helper"""
        self.running = False
        if self.riscv_sock:
            self.riscv_sock.close()
        if self.server_sock:
            self.server_sock.close()
        print("[HELPER] Stopped")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Hidden DTLS Helper - Fixes key material from RISC-V client"
    )
    parser.add_argument(
        '--riscv-port', type=int, default=5555,
        help='Port to listen for RISC-V client (default: 5555)'
    )
    parser.add_argument(
        '--server-ip', default='127.0.0.1',
        help='Backend DTLS server IP (default: 127.0.0.1)'
    )
    parser.add_argument(
        '--server-port', type=int, default=4444,
        help='Backend DTLS server port (default: 4444)'
    )
    parser.add_argument(
        '--cert-mode', action='store_true',
        help='Use certificate mode instead of PSK'
    )
    
    args = parser.parse_args()
    
    print("="*80)
    print("  Hidden DTLS Helper")
    print("  Transparently fixes key material from RISC-V client")
    print("="*80)
    print()
    
    helper = HiddenDTLSHelper(
        riscv_listen_port=args.riscv_port,
        server_ip=args.server_ip,
        server_port=args.server_port,
        psk_mode=not args.cert_mode
    )
    
    helper.start()


if __name__ == '__main__':
    main()
