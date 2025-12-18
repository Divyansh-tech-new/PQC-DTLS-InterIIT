
import re
import sys

def parse_log(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()

    output = []
    for line in lines:
        if "TCP recv" in line:
            # Extract hex bytes
            # Format: [BRIDGE] TCP recv N bytes: HEX...
            match = re.search(r'TCP recv \d+ bytes: ([0-9a-fA-F]+)\.\.\.', line)
            if match:
                hex_str = match.group(1)
                try:
                    bytes_val = bytes.fromhex(hex_str)
                    output.append(bytes_val)
                except ValueError:
                    pass
    
    full_output = b"".join(output)
    print(full_output.decode('utf-8', errors='replace'))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        parse_log(sys.argv[1])
