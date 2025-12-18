
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
        print("Connection refused. Is simulation running?")
        return

    print("Connected. Listening...")
    s.settimeout(1.0)

    # Buffer for reading
    buf = b""
    sent_abort = False
    
    # Send newline to trigger prompt if already booted
    s.send(b"\n")

    while True:
        try:
            data = s.recv(1024)
            if not data:
                break
            # Print raw data slightly sanitized
            sys.stdout.write(data.decode('utf-8', errors='ignore'))
            sys.stdout.flush()
            
            buf += data
            
            # Check for boot prompt or opportunity to interrupt
            if b"Press Q or ESC" in buf and not sent_abort:
                print("\n[DEBUG] Sending Q to abort boot...")
                s.send(b"Q")
                sent_abort = True
                
            if b"Liftoff" in buf and not sent_abort:
                 # It might be too fast, so send Q preemptively?
                 pass

            if b">" in buf:
                # We have a prompt!
                print("\n[DEBUG] Prompt detected. Sending memory dump command...")
                # Clear buffer to avoid re-triggering
                buf = b""
                # mem_dump <addr> <length>
                # BIOS > help
                # mem_dump             - Dump memory
                # Usage: mem_dump <addr> <length>
                s.send(b"mem_dump 0x40000000 64\n")
                
                # Also check where valid code should be
                # s.send(b"mem_list\n")
                
                # Give it some time to print then exit
                time.sleep(2)
                
                # Read remaining
                try:
                    while True:
                        d = s.recv(1024)
                        if not d: break
                        sys.stdout.write(d.decode('utf-8', errors='ignore'))
                except socket.timeout:
                    pass
                
                print("\n[DEBUG] Exiting interrogation.")
                break

        except socket.timeout:
            # If we idle, maybe send Enter to see if we are at prompt
            if sent_abort:
                s.send(b"\n")
            continue
        except KeyboardInterrupt:
            break

    s.close()

if __name__ == "__main__":
    main()
