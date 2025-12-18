
import socket
import time
import sys

TCP_IP = '127.0.0.1'
TCP_PORT = 1234

def main():
    print(f"Connecting to {TCP_IP}:{TCP_PORT}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TCP_IP, TCP_PORT))
    except ConnectionRefusedError:
        print("Connection refused.")
        return

    print("Connected. Sending Q blindly...")
    s.send(b"Q")
    time.sleep(0.5)
    s.send(b"\r\n") # Send Enter too
    
    s.settimeout(2.0)
    
    buf = b""
    try:
        while True:
            data = s.recv(1024)
            if not data: break
            sys.stdout.write(data.decode('utf-8', errors='ignore'))
            sys.stdout.flush()
            buf += data
            
            if b">" in buf:
                print("\n[DEBUG] Prompt detected! Dumping memory...")
                s.send(b"mem_dump 0x40000000 64\r\n")
                buf = b"" 
                
                # Wait for dump
                time.sleep(1)
                data = s.recv(4096)
                sys.stdout.write(data.decode('utf-8', errors='ignore'))
                
                # Check for magic bytes
                # 6f 00 00 0b (jal x0, ...)
                if b"6f 00 00 0b" in data or b"0000006f" in data: # formatting varies
                     print("\n[SUCCESS] Memory contains code signature!")
                else:
                     print("\n[WARNING] Memory dump does not look like expected code.")
                
                # Try to boot it explicitly?
                # s.send(b"boot 0x40000000\r\n")
                break
                
    except socket.timeout:
        print("\n[TIMEOUT] No more data.")
    
    s.close()

if __name__ == "__main__":
    main()
