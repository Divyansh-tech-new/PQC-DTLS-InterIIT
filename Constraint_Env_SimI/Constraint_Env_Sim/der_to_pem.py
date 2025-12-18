
import base64
import textwrap
import sys

def convert(filename, header="PUBLIC KEY"):
    try:
        with open(filename, 'rb') as f:
            data = f.read()
            if not data:
                print(f"Error: {filename} is empty")
                return
            
        encoded = base64.b64encode(data).decode('utf-8')
        wrapped = textwrap.fill(encoded, 64)
        
        output = filename.rsplit('.', 1)[0] + '.pem'
        with open(output, 'w') as f:
            f.write(f"-----BEGIN {header}-----\n")
            f.write(wrapped + "\n")
            f.write(f"-----END {header}-----\n")
        print(f"Created {output}")
        
    except Exception as e:
        print(f"Error converting {filename}: {e}")

if __name__ == '__main__':
    convert('pqc_certs/server-pub.der', "PUBLIC KEY") # Is it PUBLIC KEY or RAW PUBLIC KEY?
    # Standard PEM for SPKI is PUBLIC KEY.
    # RFC 7250 doesn't specify PEM header. wolfSSL likely accepts PUBLIC KEY.
