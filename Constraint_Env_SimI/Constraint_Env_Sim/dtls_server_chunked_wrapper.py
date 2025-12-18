#!/usr/bin/env python3
"""
DTLS Server Wrapper with Chunked Protocol Support
Receives chunked UDP datagrams, reassembles them, and forwards to actual DTLS server
"""

import socket
import sys
import argparse
import subprocess
import threading
import time
from chunked_udp_protocol import ChunkedSender, ChunkedReceiver


def log(msg: str):
    print(f"[WRAPPER] {msg}", flush=True)


def chunked_to_dtls(chunked_sock, dtls_sock, dtls_addr):
    """
    Receive chunked datagrams, reassemble, forward to DTLS server
    """
    log("Chunked->DTLS thread started")
    
    receiver = ChunkedReceiver(timeout=10.0)
    
    try:
        while True:
            chunked_sock.settimeout(1.0)
            try:
                data, client_addr = chunked_sock.recvfrom(2048)
            except socket.timeout:
                receiver.cleanup_stale(verbose=True)
                continue
            
            log(f"Received {len(data)} bytes from {client_addr}")
            
            # Process through chunked receiver
            complete_msg = receiver.process_datagram(data, verbose=True)
            
            if complete_msg:
                log(f"✓ Reassembled complete message: {len(complete_msg)} bytes")
                
                # Forward to actual DTLS server
                dtls_sock.sendto(complete_msg, dtls_addr)
                log(f"Forwarded to DTLS server at {dtls_addr}")
                
                # Show stats
                stats = receiver.get_stats()
                log(f"Stats: {stats}")
    
    except Exception as e:
        log(f"Chunked->DTLS exception: {e}")


def dtls_to_chunked(dtls_sock, chunked_sock, client_addr_map):
    """
    Receive from DTLS server, chunk, send back to client
    """
    log("DTLS->Chunked thread started")
    
    sender = ChunkedSender(chunked_sock, ("0.0.0.0", 0))  # Will update address dynamically
    
    try:
        while True:
            data, server_addr = dtls_sock.recvfrom(65536)
            
            log(f"Received {len(data)} bytes from DTLS server")
            
            # Find the client address (stored from incoming)
            # For now, we'll use the last known client
            if not hasattr(dtls_to_chunked, 'last_client'):
                log("WARNING: No client address known yet, dropping packet")
                continue
            
            client = dtls_to_chunked.last_client
            
            # Send chunked
            sender.remote_addr = client
            msg_id = sender.send_message(data, verbose=True)
            log(f"Sent response as chunked message #{msg_id} to {client}")
    
    except Exception as e:
        log(f"DTLS->Chunked exception: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="DTLS Server Wrapper with Chunked Protocol"
    )
    parser.add_argument("--listen-port", type=int, required=True,
                      help="Port to listen for chunked datagrams")
    parser.add_argument("--dtls-server", required=True,
                      help="Actual DTLS server address (host:port)")
    
    args = parser.parse_args()
    
    dtls_host, dtls_port = args.dtls_server.split(':')
    dtls_port = int(dtls_port)
    dtls_addr = (dtls_host, dtls_port)
    
    log("=" * 80)
    log("DTLS Server Wrapper with Chunked Protocol")
    log(f"  Listening on: 0.0.0.0:{args.listen_port} (chunked)")
    log(f"  DTLS server:  {dtls_host}:{dtls_port}")
    log("=" * 80)
    
    # Create sockets
    chunked_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    chunked_sock.bind(("0.0.0.0", args.listen_port))
    log(f"Chunked socket listening on port {args.listen_port}")
    
    dtls_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dtls_sock.bind(("127.0.0.1", 0))  # Let OS choose port
    local_port = dtls_sock.getsockname()[1]
    log(f"DTLS forwarding socket bound to port {local_port}")
    
    # Track client addresses
    client_addr_map = {}
    
    # Start relay threads
    t1 = threading.Thread(
        target=chunked_to_dtls,
        args=(chunked_sock, dtls_sock, dtls_addr),
        daemon=True
    )
    
    t2 = threading.Thread(
        target=dtls_to_chunked,
        args=(dtls_sock, chunked_sock, client_addr_map),
        daemon=True
    )
    
    t1.start()
    t2.start()
    
    log("Wrapper threads started. Press Ctrl+C to stop.")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("\nShutting down...")
    finally:
        chunked_sock.close()
        dtls_sock.close()


if __name__ == "__main__":
    main()
