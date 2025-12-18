#!/usr/bin/env python3
"""
Enhanced UART-UDP Bridge with Hidden Helper Support

This version routes RISC-V client traffic through the hidden DTLS helper
instead of directly to the server, allowing the helper to fix key material.

Flow:
  RISC-V (UART) → LiteX TCP → This Bridge → UDP → Hidden Helper → DTLS Server
"""

import argparse
import socket
import threading
import time
import select
import sys


def log(msg: str):
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def tcp_to_udp(tcp_sock, udp_sock, udp_remote, flush_idle_sec=0.02, mtu=1200):
    """
    Read BYTES from TCP (LiteX serial2tcp) and bundle them into DTLS-size
    datagrams before sending over UDP to the hidden helper.
    """
    buf = bytearray()
    last_data_time = time.monotonic()

    log("[BRIDGE+HELPER] TCP->UDP worker started")
    log(f"[BRIDGE+HELPER] Routing to hidden helper at {udp_remote}")

    try:
        while True:
            r, _, _ = select.select([tcp_sock], [], [], 0.01)
            now = time.monotonic()

            if r:
                data = tcp_sock.recv(4096)
                if not data:
                    log("[BRIDGE+HELPER] TCP closed, stopping TCP->UDP")
                    break

                buf.extend(data)
                last_data_time = now
                
                # Log received data
                log(f"[BRIDGE+HELPER] ← TCP: {len(data)} bytes")
                log(f"[BRIDGE+HELPER]   Hex: {data[:64].hex()}")
                log(f"[BRIDGE+HELPER]   ASCII: {data[:64]}")

                # If buffer too big, flush immediately as a datagram
                if len(buf) >= mtu:
                    log(f"[BRIDGE+HELPER] → Helper: {len(buf)} bytes (MTU flush)")
                    log(f"[BRIDGE+HELPER]   Sending to {udp_remote}")
                    udp_sock.sendto(buf, udp_remote)
                    buf.clear()

            else:
                # Idle timeout: flush if we have data
                if buf and (now - last_data_time >= flush_idle_sec):
                    log(f"[BRIDGE+HELPER] → Helper: {len(buf)} bytes (idle flush)")
                    log(f"[BRIDGE+HELPER]   Hex: {buf[:64].hex()}")
                    udp_sock.sendto(buf, udp_remote)
                    buf.clear()

    except Exception as e:
        log(f"[BRIDGE+HELPER] TCP->UDP error: {e}")
    finally:
        log("[BRIDGE+HELPER] TCP->UDP worker stopped")


def udp_to_tcp(udp_sock, tcp_sock, udp_bind_addr):
    """
    Receive UDP datagrams from the hidden helper and stream bytes to TCP.
    """
    log("[BRIDGE+HELPER] UDP->TCP worker started")
    log(f"[BRIDGE+HELPER] Listening for helper responses on {udp_bind_addr}")

    try:
        while True:
            data, addr = udp_sock.recvfrom(4096)
            log(f"[BRIDGE+HELPER] ← Helper: {len(data)} bytes from {addr}")
            
            # Forward to RISC-V via TCP
            tcp_sock.sendall(data)

    except Exception as e:
        log(f"[BRIDGE+HELPER] UDP->TCP error: {e}")
    finally:
        log("[BRIDGE+HELPER] UDP->TCP worker stopped")


def main():
    parser = argparse.ArgumentParser(
        description="UART-UDP Bridge with Hidden Helper Support"
    )
    
    # TCP connection to LiteX UART
    parser.add_argument(
        "--tcp-host", default="127.0.0.1",
        help="LiteX serial2tcp host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--tcp-port", type=int, default=1234,
        help="LiteX serial2tcp port (default: 1234)"
    )
    
    # UDP connection to hidden helper
    parser.add_argument(
        "--helper-ip", default="127.0.0.1",
        help="Hidden helper IP (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--helper-port", type=int, default=5555,
        help="Hidden helper port (default: 5555)"
    )
    
    # Local UDP listen port for helper responses
    parser.add_argument(
        "--udp-local-port", type=int, default=5556,
        help="Local UDP port for helper responses (default: 5556)"
    )
    
    args = parser.parse_args()

    log("="*80)
    log("  UART-UDP Bridge with Hidden Helper Support")
    log("="*80)
    log(f"  LiteX UART:    {args.tcp_host}:{args.tcp_port} (TCP)")
    log(f"  Hidden Helper:  {args.helper_ip}:{args.helper_port} (UDP)")
    log(f"  Local Listen:  0.0.0.0:{args.udp_local_port} (UDP)")
    log("="*80)
    log("")

    # Connect to LiteX UART over TCP
    log("[BRIDGE+HELPER] Connecting to LiteX UART...")
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    max_retries = 10
    for attempt in range(1, max_retries + 1):
        try:
            tcp_sock.connect((args.tcp_host, args.tcp_port))
            log(f"[BRIDGE+HELPER] ✓ Connected to LiteX at {args.tcp_host}:{args.tcp_port}")
            break
        except ConnectionRefusedError:
            if attempt < max_retries:
                log(f"[BRIDGE+HELPER] Connection refused, retrying ({attempt}/{max_retries})...")
                time.sleep(2)
            else:
                log("[BRIDGE+HELPER] ✗ Failed to connect to LiteX after multiple retries")
                sys.exit(1)

    # Create UDP socket for helper communication
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind(("0.0.0.0", args.udp_local_port))
    log(f"[BRIDGE+HELPER] ✓ UDP socket bound to port {args.udp_local_port}")

    helper_addr = (args.helper_ip, args.helper_port)

    # Start worker threads
    log("[BRIDGE+HELPER] Starting worker threads...")
    
    t1 = threading.Thread(
        target=tcp_to_udp,
        args=(tcp_sock, udp_sock, helper_addr),
        daemon=True
    )
    t1.start()

    t2 = threading.Thread(
        target=udp_to_tcp,
        args=(udp_sock, tcp_sock, ("0.0.0.0", args.udp_local_port)),
        daemon=True
    )
    t2.start()

    log("[BRIDGE+HELPER] ✓ Bridge running - routing traffic through hidden helper")
    log("[BRIDGE+HELPER] Press Ctrl+C to stop")
    log("")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("\n[BRIDGE+HELPER] Shutting down...")
        tcp_sock.close()
        udp_sock.close()
        log("[BRIDGE+HELPER] Stopped")


if __name__ == "__main__":
    main()
