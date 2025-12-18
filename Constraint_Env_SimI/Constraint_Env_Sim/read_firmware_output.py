#!/usr/bin/env python3
"""
Capture actual firmware output by connecting directly to simulation UART
"""
import socket
import time
import sys
import subprocess
import os
import signal

def main():
    # Start simulation
    print("Starting LiteX simulation...")
    env = os.environ.copy()
    pythonpath_dirs = []
    for item in os.listdir('.'):
        if item.startswith('pythondata'):
            pythonpath_dirs.append(os.path.abspath(item))
    pythonpath_dirs.extend(['litex', 'migen'])
    env['PYTHONPATH'] = ':'.join(pythonpath_dirs) + ':' + env.get('PYTHONPATH', '')
    
    sim_proc = subprocess.Popen([
        'python3', 'litex/litex/tools/litex_sim.py',
        '--csr-json', 'csr.json',
        '--cpu-type=vexriscv',
        '--cpu-variant=full',
        '--integrated-main-ram-size=0x02000000',
        '--ram-init=boot.bin',
        '--output-dir=build/sim_sp',
        '--non-interactive'
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    
    print(f"Simulation started (PID: {sim_proc.pid})")
    print("Waiting for UART port to open...")
    
    # Wait for port
    for i in range(30):
        time.sleep(1)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect(('127.0.0.1', 1234))
            print("Connected to UART!")
            break
        except:
            if i % 5 == 4:
                print(f"  Still waiting... ({i+1}s)")
            sock.close()
    else:
        print("ERROR: Could not connect to UART")
        sim_proc.kill()
        return
    
    # Read firmware output
    print("\n" + "="*80)
    print("FIRMWARE OUTPUT:")
    print("="*80)
    
    sock.settimeout(5.0)
    data = b''
    try:
        while len(data) < 5000:
            chunk = sock.recv(100)
            if not chunk:
                break
            data += chunk
            sys.stdout.write(chunk.decode('utf-8', errors='replace'))
            sys.stdout.flush()
    except socket.timeout:
        pass
    except Exception as e:
        print(f"\nError: {e}")
    
    sock.close()
    
    print("\n" + "="*80)
    print(f"Total received: {len(data)} bytes")
    print("="*80)
    
    # Show hex if needed
    if len(data) < 500:
        print("\nHEX DUMP:")
        print(' '.join(f'{b:02x}' for b in data))
    
    # Cleanup
    print("\nKilling simulation...")
    sim_proc.terminate()
    try:
        sim_proc.wait(timeout=5)
    except:
        sim_proc.kill()
    
    print("Done!")

if __name__ == '__main__':
    main()
