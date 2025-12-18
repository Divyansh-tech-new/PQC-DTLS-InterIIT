#!/usr/bin/env python3
"""
Capture and display firmware debug output from UART
"""
import socket
import time
import sys

def capture_uart_output(host='127.0.0.1', port=1234, timeout=5):
    """Connect to UART and display all output"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        
        print(f"Connecting to {host}:{port}...")
        sock.connect((host, port))
        sock.settimeout(timeout)
        
        print("Connected! Reading firmware output...\n")
        print("=" * 80)
        
        buffer = b''
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                buffer += chunk
                # Print as we receive
                try:
                    text = chunk.decode('utf-8', errors='ignore')
                    print(text, end='', flush=True)
                except:
                    print(f"<binary: {len(chunk)} bytes>", end='', flush=True)
            except socket.timeout:
                break
            except Exception as e:
                print(f"\nError reading: {e}")
                break
        
        print("\n" + "=" * 80)
        print(f"\nTotal captured: {len(buffer)} bytes")
        print("\nFull buffer (hex):")
        print(buffer.hex(' ', 1))
        print("\nFull buffer (text):")
        print(buffer.decode('utf-8', errors='replace'))
        
        sock.close()
        return buffer
        
    except Exception as e:
        print(f"Error: {e}")
        return None

if __name__ == "__main__":
    capture_uart_output()
