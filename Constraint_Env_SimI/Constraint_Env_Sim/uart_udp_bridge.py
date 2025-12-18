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


def tcp_to_udp(tcp_sock, udp_sock, udp_remote, flush_idle_sec=0.1, mtu=4096):
    """
    Read BYTES from TCP (LiteX serial2tcp) and bundle them into valid DTLS datagrams
    before sending over UDP.
    
    CRITICAL: Parses DTLS Record Header to ensure full packets are sent.
    Header format (13 bytes):
      [0]: Content Type
      [1-2]: Version
      [3-4]: Epoch
      [5-10]: Sequence Number
      [11-12]: Length (Big Endian)
    """
    buf = bytearray()
    last_data_time = time.monotonic()
    
    MIN_HEADER_LEN = 13

    log("[BRIDGE] TCP->UDP worker started (Smart Buffering Mode)")

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
                
                # Debug: Print received chunk size
                if len(data) > 0:
                   log(f"[BRIDGE] TCP recv {len(data)} bytes. Total buf: {len(buf)}")

            # --- PROCESS BUFFER ---
            # Attempt to extract as many full DTLS records as possible
            while True:
                if len(buf) < MIN_HEADER_LEN:
                    # Not enough for a header, wait for more data
                    break
                
                # Parse Length from DTLS Header (Bytes 11-12)
                # content_type = buf[0]
                # version = (buf[1] << 8) | buf[2]
                payload_len = (buf[11] << 8) | buf[12]
                total_record_len = MIN_HEADER_LEN + payload_len
                
                if len(buf) >= total_record_len:
                    # We have a full record! Extract and send.
                    packet = buf[:total_record_len]
                    del buf[:total_record_len]
                    
                    udp_sock.sendto(packet, udp_remote)
                    # log(f"[BRIDGE] TCP->UDP: Reassembled & sent {len(packet)} bytes (DTLS Record)")
                else:
                    # Wait for rest of this record
                    break
            
            # --- FALLBACK / TIMEOUT ---
            # If buffer has 'junk' that doesn't look like DTLS or we are stuck waiting too long
            # (e.g. non-DTLS debug prints), flush it eventually.
            # DTLS ClientHello usually starts with 0x16 (Handshake)
            if buf:
                 # If it doesn't look like DTLS (0x16=Handshake, 0x15=Alert, 0x17=App, 0x14=ChangeCipher)
                 # AND we've been idle, just flush it (likely debug text).
                 is_dtls = (buf[0] in [0x14, 0x15, 0x16, 0x17])
                 
                 if (not is_dtls) and (now - last_data_time) >= 0.05:
                     # udp_sock.sendto(buf, udp_remote)
                     with open('logs/firmware_debug.txt', 'ab') as f:
                         f.write(buf)
                     log(f"[BRIDGE] TCP->UDP: Dropped {len(buf)} bytes of non-DTLS data (debug text)")
                     buf.clear()
                 
                 # Stuck DTLS fragment? Force flush if VERY stale (to avoid total deadlock)
                 elif (now - last_data_time) >= 2.0:
                     udp_sock.sendto(buf, udp_remote)
                     log(f"[BRIDGE] TCP->UDP: Flushed {len(buf)} bytes (Stale Fragment!)")
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
    udp_sock.bind((args.udp_local_ip, 5559))

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
