
import re
import os

def parse_c_array(content, array_name):
    # dynamic regex to capture the array content
    pattern = r'const unsigned char ' + array_name + r'\[\] = \{(.*?)\};'
    match = re.search(pattern, content, re.DOTALL)
    if not match:
        print(f"Error: Could not find array {array_name}")
        return None
    
    hex_values = match.group(1).replace('\n', '').replace(' ', '').split(',')
    # filter empty strings
    hex_values = [x for x in hex_values if x]
    
    # helper to convert 0xAB to bytes
    byte_array = bytearray()
    for h in hex_values:
        if h.startswith('0x'):
            byte_array.append(int(h, 16))
    return byte_array

def main():
    header_path = 'boot/pqc_certs.h'
    output_dir = 'pqc_certs'
    
    if not os.path.exists(header_path):
        print(f"Error: {header_path} not found")
        return

    with open(header_path, 'r') as f:
        content = f.read()
        
    mappings = [
        ('ca_public_key', 'ca-pub.der'),
        ('server_public_key', 'server-pub.der'),
        ('server_private_key', 'server-key.der'),
        ('client_public_key', 'client-pub.der'),
        ('client_private_key', 'client-key.der'),
    ]
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    for var_name, filename in mappings:
        data = parse_c_array(content, var_name)
        if data:
            out_path = os.path.join(output_dir, filename)
            with open(out_path, 'wb') as f:
                f.write(data)
            print(f"Restored {filename} ({len(data)} bytes)")
        else:
            print(f"Failed to extract {var_name}")

if __name__ == '__main__':
    main()
