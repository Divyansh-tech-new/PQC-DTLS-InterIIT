#!/usr/bin/env python3
"""
Updated UART <-> UDP Bridge with Chunked Protocol
Properly reassembles large DTLS packets using chunk framing
"""

import argparse
import socket
import threading
import time
import select
import sys
from chunked_udp_protocol import ChunkedSender, ChunkedReceiver, HEADER_SIZE


def log(msg: str):
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def tcp_to_udp_chunked(tcp_sock, udp_sock, udp_remote):
    """
    Read DTLS packets from TCP and send using chunked protocol.
    Uses DTLS header parsing to identify complete records, then chunks them.
    """
    buf = bytearray()
    last_data_time = time.monotonic()
    MIN_HEADER_LEN = 13
    
    sender = ChunkedSender(udp_sock, udp_remote)
    
    log("[BRIDGE] TCP->UDP worker started (CHUNKED MODE)")

    try:
        while True:
            r, _, _ = select.select([tcp_sock], [], [], 0.01)
            now = time.monotonic()

            if r:
                data = tcp_sock.recv(4096)
                if not data:
                    log("[BRIDGE] TCP closed, stopping TCP->UDP")
                    break

                buf.extend(data)
                last_data_time = now
                
                log(f"[BRIDGE] TCP recv {len(data)} bytes. Buffer: {len(buf)} bytes")

            # Try to extract complete DTLS records
            while True:
                if len(buf) < MIN_HEADER_LEN:
                    break
                
                # Check if this looks like DTLS
                content_type = buf[0]
                if content_type not in [0x14, 0x15, 0x16, 0x17, 0x18]:
                    # Not DTLS, check if it's debug text
                    if (now - last_data_time) >= 0.05:
                        # Flush non-DTLS data
                        log(f"[BRIDGE] Dropping {len(buf)} bytes of non-DTLS data")
                        buf.clear()
                    break
                
                # Parse DTLS length
                payload_len = (buf[11] << 8) | buf[12]
                total_record_len = MIN_HEADER_LEN + payload_len
                
                # Sanity check
                if payload_len > 16384:  # Max DTLS record
                    log(f"[BRIDGE] WARNING: Suspicious DTLS length {payload_len}")
                    buf.clear()
                    break
                
                if len(buf) >= total_record_len:
                    # Complete DTLS record!
                    dtls_record = bytes(buf[:total_record_len])
                    del buf[:total_record_len]
                    
                    log(f"[BRIDGE] Extracted complete DTLS record: {len(dtls_record)} bytes")
                    
                    # Send using chunked protocol
                    msg_id = sender.send_message(dtls_record, verbose=True)
                    log(f"[BRIDGE] Sent as chunked message #{msg_id}")
                else:
                    # Need more data
                    break
            
            # Timeout check for stuck fragments
            if buf and (now - last_data_time) >= 2.0:
                log(f"[BRIDGE] WARNING: Flushing stale buffer ({len(buf)} bytes)")
                buf.clear()

    except Exception as e:
        log(f"[BRIDGE] TCP->UDP exception: {e!r}")
    finally:
        try:
            tcp_sock.shutdown(socket.SHUT_RD)
        except Exception:
            pass
        log("[BRIDGE] TCP->UDP worker exiting")


def udp_to_tcp_chunked(udp_sock, tcp_sock):
    """
    Receive chunked UDP datagrams, reassemble, and forward to TCP.
    """
    log("[BRIDGE] UDP->TCP worker started (CHUNKED MODE)")
    
    receiver = ChunkedReceiver(timeout=5.0)
    
    try:
        while True:
            udp_sock.settimeout(1.0)
            try:
                data, addr = udp_sock.recvfrom(2048)
            except socket.timeout:
                # Cleanup stale messages
                receiver.cleanup_stale(verbose=True)
                continue
            
            if not data:
                continue
            
            log(f"[BRIDGE] UDP recv {len(data)} bytes from {addr}")
            
            # Process through chunked receiver
            complete_msg = receiver.process_datagram(data, verbose=True)
            
            if complete_msg:
                # Forward complete message to TCP
                tcp_sock.sendall(complete_msg)
                log(f"[BRIDGE] UDP->TCP: Forwarded {len(complete_msg)} bytes to LiteX")
                
                # Show stats
                stats = receiver.get_stats()
                log(f"[BRIDGE] Stats: {stats}")
            
    except Exception as e:
        log(f"[BRIDGE] UDP->TCP exception: {e!r}")
    finally:
        try:
            tcp_sock.shutdown(socket.SHUT_WR)
        except Exception:
            pass
        log("[BRIDGE] UDP->TCP worker exiting")


def main():
    parser = argparse.ArgumentParser(
        description="UART <-> UDP bridge with chunked protocol for DTLS 1.3 PQC"
    )
    parser.add_argument("--tcp-host", required=True, help="LiteX serial2tcp host")
    parser.add_argument("--tcp-port", required=True, type=int, help="LiteX serial2tcp port")
    parser.add_argument("--udp-local-ip", required=True, help="Local IP for UDP")
    parser.add_argument("--udp-remote-ip", required=True, help="DTLS server IP")
    parser.add_argument("--udp-remote-port", required=True, type=int, help="DTLS server port")

    args = parser.parse_args()

    tcp_addr = (args.tcp_host, args.tcp_port)
    udp_remote = (args.udp_remote_ip, args.udp_remote_port)

    log("=" * 80)
    log(" UART-to-UDP Bridge with CHUNKED PROTOCOL")
    log(f"  TCP  : {args.tcp_host}:{args.tcp_port}")
    log(f"  UDP  : {args.udp_remote_ip}:{args.udp_remote_port}")
    log("=" * 80)

    # Connect TCP
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.connect(tcp_addr)
    log(f"[BRIDGE] Connected to LiteX at {tcp_addr}")

    # Create UDP socket
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((args.udp_local_ip, 0))
    local_port = udp_sock.getsockname()[1]
    log(f"[BRIDGE] UDP socket bound to {args.udp_local_ip}:{local_port}")

    # Start threads
    t1 = threading.Thread(target=tcp_to_udp_chunked, args=(tcp_sock, udp_sock, udp_remote), daemon=True)
    t2 = threading.Thread(target=udp_to_tcp_chunked, args=(udp_sock, tcp_sock), daemon=True)

    t1.start()
    t2.start()

    log("[BRIDGE] Bridge threads started. Press Ctrl+C to stop.")

    try:
        t1.join()
        t2.join()
    except KeyboardInterrupt:
        log("\n[BRIDGE] Shutting down...")
    finally:
        tcp_sock.close()
        udp_sock.close()


if __name__ == "__main__":
    main()
