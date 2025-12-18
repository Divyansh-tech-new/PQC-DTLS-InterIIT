# DTLS 1.3 with Post-Quantum Cryptography Demo

This project demonstrates DTLS 1.3 with Post-Quantum Cryptography (PQC) running on a LiteX RISC-V simulation with mutual authentication using Dilithium signatures and ML-KEM (Kyber) key exchange.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  LiteX RISC-V Simulation (VexRISC-V CPU)                       │
│  ┌───────────────────────────────────────────────────┐         │
│  │ DTLS 1.3 Client Firmware (boot.fbi)               │         │
│  │  - wolfSSL with PQC support                       │         │
│  │  - Dilithium signatures                           │         │
│  │  - ML-KEM (Kyber) key exchange                    │         │
│  │  - Client certificate authentication              │         │
│  └───────────────────────────────────────────────────┘         │
│                        ↕ UART                                   │
└─────────────────────────────────────────────────────────────────┘
                         ↕ TCP (localhost:1234)
┌─────────────────────────────────────────────────────────────────┐
│  UART-UDP Bridge (Python)                                       │
│  - Converts UART ↔ UDP packets                                 │
└─────────────────────────────────────────────────────────────────┘
                         ↕ UDP (localhost:4444)
┌─────────────────────────────────────────────────────────────────┐
│  DTLS 1.3 PQC Server (C program)                               │
│  - wolfSSL with PQC support                                    │
│  - Server certificate authentication                           │
│  - Handles DTLS handshake and secure communication            │
└─────────────────────────────────────────────────────────────────┘
```

## Features

- **Post-Quantum Cryptography:**
  - Dilithium digital signatures (quantum-resistant)
  - ML-KEM (Kyber) key exchange
  - Hybrid classical + PQC approach

- **DTLS 1.3:** Latest datagram transport layer security
- **Mutual Authentication:** Both client and server verify certificates
- **RISC-V Platform:** Runs on LiteX simulation with VexRISC-V CPU
- **Embedded-optimized:** Minimal memory footprint for constrained environments

## Prerequisites

### System Requirements
- Linux (Ubuntu/Debian recommended)
- Python 3.8 or later
- GCC RISC-V toolchain
- 4GB RAM minimum

### Required Packages
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    gcc-riscv64-unknown-elf \
    libtool \
    autoconf \
    automake \
    python3 python3-pip \
    git
```

### Python Dependencies
```bash
pip3 install --user meson ninja
pip3 install --user litex
pip3 install --user git+https://github.com/litex-hub/pythondata-cpu-vexriscv.git
pip3 install --user git+https://github.com/litex-hub/pythondata-software-compiler_rt.git
pip3 install --user git+https://github.com/litex-hub/pythondata-software-picolibc.git
pip3 install --user git+https://github.com/litex-hub/pythondata-misc-tapcfg.git
```

## Installation

### 1. Install wolfSSL with PQC Support

First, clone wolfSSL:
```bash
cd /usr/local/src
sudo git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
sudo git checkout master  # or specific version
```

Then build and install:
```bash
cd /path/to/this/project
sudo ./install_wolfssl.sh
```

This will build wolfSSL with:
- DTLS 1.3 support
- Dilithium (all security levels)
- ML-KEM (Kyber) 512/768/1024
- Required cipher suites

### 2. Generate PQC Certificates

```bash
./generate_pqc_certs.sh
```

This creates:
- `pqc_certs/server-dilithium-cert.pem` - Server certificate
- `pqc_certs/server-dilithium-key.pem` - Server private key
- `pqc_certs/client-dilithium-cert.pem` - Client certificate
- `pqc_certs/client-dilithium-key.pem` - Client private key
- `pqc_certs/ca-dilithium-cert.pem` - CA certificate

## Building and Running

### Step 1: Build the Firmware

```bash
chmod +x build_firmware.sh
./build_firmware.sh
```

This compiles the RISC-V firmware and creates:
- `boot.bin` - Raw binary
- `boot.elf` - ELF executable
- `boot.fbi` - LiteX bootable image

### Step 2: Build the DTLS Server

```bash
cd dtls_server
make
cd ..
```

### Step 3: Run the Complete Demo

```bash
chmod +x run_demo.sh
./run_demo.sh
```

This script will:
1. Start the DTLS server (listening on UDP port 4444)
2. Start the LiteX RISC-V simulation
3. Start the UART-UDP bridge
4. Monitor the DTLS handshake completion

## Expected Output

When successful, you should see:

```
===============================================================================
  FINAL RESULTS
===============================================================================

✓✓✓ SUCCESS! DTLS 1.3 Post-Quantum Handshake Completed ✓✓✓

Cryptographic Details:
  - Key Exchange: ML-KEM (Kyber) hybrid
  - Signatures: Dilithium (quantum-resistant)
  - Cipher Suite: TLS_AES_128_GCM_SHA256
  - Authentication: Mutual (Client + Server certificates)
```

## Project Structure

```
.
├── run_demo.sh                 # Main demo script
├── build_firmware.sh           # Build RISC-V firmware
├── generate_pqc_certs.sh       # Generate PQC certificates
├── install_wolfssl.sh          # Build and install wolfSSL
├── boot/                       # RISC-V firmware source
│   ├── main.c                 # Client firmware with DTLS
│   ├── Makefile               # Firmware build system
│   ├── pqc_certs.h            # Embedded certificates
│   └── wolfcrypt/             # wolfSSL crypto library
├── dtls_server/               # DTLS server application
│   ├── dtls_pqc_server.c     # Server implementation
│   └── Makefile              # Server build system
├── pqc_certs/                # PQC certificates directory
├── uart_udp_bridge.py        # UART-to-UDP bridge
├── test_pipeline.sh          # Quick communication test
├── test_udp_server.py        # Simple UDP echo server
└── simulate_handshake.py     # Handshake simulation tool
```

## Testing

### Quick Pipeline Test (without DTLS)
Test the communication pipeline without cryptography:
```bash
./test_pipeline.sh
```

### Manual Component Testing

Start each component separately for debugging:

```bash
# Terminal 1: Start server
cd dtls_server && ./dtls_pqc_server

# Terminal 2: Start simulation
litex_sim --csr-json csr.json --cpu-type=vexriscv \
    --cpu-variant=full --integrated-main-ram-size=0x06400000 \
    --ram-init=boot.fbi

# Terminal 3: Start bridge
python3 uart_udp_bridge.py --tcp-port 1234 --udp-remote-port 4444
```

## Troubleshooting

### Build fails with "wolfssl.h not found"
- Ensure wolfSSL is installed: `sudo ldconfig -v | grep wolfssl`
- Check install path: `ls /usr/local/include/wolfssl/`
- Rebuild wolfSSL: `sudo ./install_wolfssl.sh`

### Simulation doesn't start
- Check RISC-V toolchain: `riscv64-unknown-elf-gcc --version`
- Verify boot.fbi exists: `ls -lh boot.fbi`
- Check dependencies: `pip3 list | grep litex`

### Handshake timeout
- Verify all three components are running
- Check logs in `logs/` directory
- Ensure UDP port 4444 is not blocked
- Try increasing timeout in run_demo.sh

### Certificate errors
- Regenerate certificates: `./generate_pqc_certs.sh`
- Check certificate validity: `openssl x509 -in pqc_certs/server-dilithium-cert.pem -text -noout`

## Performance Notes

- **Handshake Time:** ~30-60 seconds on typical hardware
- **Dilithium Signature:** ~20-40ms on RISC-V simulation
- **ML-KEM Key Exchange:** ~15-30ms
- **Memory Usage:** ~2MB RAM for client firmware

The simulation runs at approximately 10MHz, so operations take longer than real hardware.

## Technical Details

### Cipher Suites Supported
- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256

### PQC Algorithms
- **Dilithium2:** NIST Level 2 security (~128-bit)
- **Dilithium3:** NIST Level 3 security (~192-bit)
- **Dilithium5:** NIST Level 5 security (~256-bit)
- **ML-KEM-512:** 512-bit key (NIST Level 1)
- **ML-KEM-768:** 768-bit key (NIST Level 3)
- **ML-KEM-1024:** 1024-bit key (NIST Level 5)

## Security Considerations

- This is a demonstration/research implementation
- Certificates are self-signed and for testing only
- Use proper PKI and certificate management in production
- Review wolfSSL security advisories regularly
- Consider hardware random number generator for production

## License

This project uses wolfSSL which is dual-licensed (GPLv2 and commercial).
See wolfSSL documentation for licensing details.

## References

- [wolfSSL PQC Documentation](https://www.wolfssl.com/documentation/)
- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [LiteX Framework](https://github.com/enjoy-digital/litex)
- [Dilithium Specification](https://pq-crystals.org/dilithium/)
- [ML-KEM (Kyber) Specification](https://pq-crystals.org/kyber/)
