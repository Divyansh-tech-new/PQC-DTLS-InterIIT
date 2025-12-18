#!/usr/bin/env python3
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
    datagrams before sending over UDP.

    - Accumulates bytes into a buffer.
    - If no new TCP data arrives for `flush_idle_sec`, flush buffer as one UDP datagram.
    - If buffer grows beyond `mtu`, flush immediately.
    """
    buf = bytearray()
    last_data_time = time.monotonic()

    log("[BRIDGE] TCP->UDP worker started")

    try:
        while True:
            # Wait up to 10ms for TCP data
            r, _, _ = select.select([tcp_sock], [], [], 0.01)
            now = time.monotonic()

            if r:
                data = tcp_sock.recv(4096)
                if not data:
                    log("[BRIDGE] TCP closed, stopping TCP->UDP")
                    break

                buf.extend(data)
                last_data_time = now

                # If buffer too big, flush immediately as a datagram
                if len(buf) >= mtu:
                    udp_sock.sendto(buf, udp_remote)
                    log(f"[BRIDGE] TCP->UDP: sent {len(buf)} bytes (MTU flush)")
                    buf.clear()

            else:
                # No TCP data this tick: if we have something buffered
                # AND we've been idle long enough, flush as 1 datagram.
                if buf and (now - last_data_time) >= flush_idle_sec:
                    udp_sock.sendto(buf, udp_remote)
                    log(f"[BRIDGE] TCP->UDP: sent {len(buf)} bytes (idle flush)")
                    buf.clear()

    except Exception as e:
        log(f"[BRIDGE] TCP->UDP exception: {e!r}")
    finally:
        try:
            tcp_sock.shutdown(socket.SHUT_RD)
        except Exception:
            pass
        log("[BRIDGE] TCP->UDP worker exiting")


def udp_to_tcp(udp_sock, tcp_sock):
    """
    For each UDP datagram from the DTLS server, write the raw bytes
    into the TCP connection (LiteX serial2tcp).
    """
    log("[BRIDGE] UDP->TCP worker started")
    try:
        while True:
            data, addr = udp_sock.recvfrom(4096)
            if not data:
                continue
            tcp_sock.sendall(data)
            # Optional debug:
            # log(f"[BRIDGE] UDP->TCP: received {len(data)} bytes from {addr}")
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
        description="UART <-> UDP bridge for DTLS 1.3 PQC over LiteX serial2tcp"
    )
    parser.add_argument("--tcp-host", required=True, help="LiteX serial2tcp host (e.g., 127.0.0.1)")
    parser.add_argument("--tcp-port", required=True, type=int, help="LiteX serial2tcp TCP port (e.g., 1234)")
    parser.add_argument("--udp-local-ip", required=True, help="Local IP to bind UDP socket (e.g., 192.168.1.100)")
    parser.add_argument("--udp-remote-ip", required=True, help="DTLS server IP (e.g., 192.168.1.100)")
    parser.add_argument("--udp-remote-port", required=True, type=int, help="DTLS server UDP port (e.g., 4444)")

    args = parser.parse_args()

    tcp_addr = (args.tcp_host, args.tcp_port)
    udp_remote = (args.udp_remote_ip, args.udp_remote_port)

    log("============================================================")
    log(" UART-to-UDP Bridge for DTLS 1.3 PQC")
    log(f"  TCP  : {args.tcp_host}:{args.tcp_port}")
    log(f"  UDP  : {args.udp_remote_ip}:{args.udp_remote_port}")
    log(f"  Local UDP bind IP: {args.udp_local_ip}")
    log("============================================================")

    # --- Connect to LiteX serial2tcp (TCP side) ---
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    while True:
        try:
            log(f"[BRIDGE] Connecting to LiteX UART TCP at {tcp_addr[0]}:{tcp_addr[1]} ...")
            tcp_sock.connect(tcp_addr)
            log("[BRIDGE] Connected to LiteX TCP UART.")
            break
        except OSError as e:
            log(f"[BRIDGE] TCP connect failed: {e}, retrying in 1s...")
            time.sleep(1)

    # --- Prepare UDP socket (to DTLS server) ---
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Bind to specific local IP, any port.
    udp_sock.bind((args.udp_local_ip, 0))

    # --- Start workers ---
    t1 = threading.Thread(target=tcp_to_udp, args=(tcp_sock, udp_sock, udp_remote), daemon=True)
    t2 = threading.Thread(target=udp_to_tcp, args=(udp_sock, tcp_sock), daemon=True)

    t1.start()
    t2.start()

    # Keep main thread alive while workers run.
    try:
        while t1.is_alive() and t2.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        log("[BRIDGE] KeyboardInterrupt, exiting.")
    finally:
        tcp_sock.close()
        udp_sock.close()


if __name__ == "__main__":
    main()
