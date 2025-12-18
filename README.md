# PQC-DTLS 1.3 for RISC-V IoT Devices

A complete implementation of Post-Quantum Cryptography (PQC) enabled DTLS 1.3 for bare-metal RISC-V IoT devices, featuring Dilithium signatures and ML-KEM (Kyber) key exchange.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![RISC-V](https://img.shields.io/badge/RISC--V-VexRiscv-blue.svg)](https://github.com/SpinalHDL/VexRiscv)
[![wolfSSL](https://img.shields.io/badge/wolfSSL-5.6+-green.svg)](https://www.wolfssl.com/)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [1. System Dependencies](#1-system-dependencies)
  - [2. Python Packages](#2-python-packages)
  - [3. wolfSSL with PQC Support](#3-wolfssl-with-pqc-support)
  - [4. Certificate Generation](#4-certificate-generation)
- [Building the Project](#building-the-project)
  - [Build RISC-V Firmware](#build-risc-v-firmware)
  - [Build DTLS Server](#build-dtls-server)
- [Running the Demo](#running-the-demo)
  - [Quick Start (Automated)](#quick-start-automated)
  - [Manual Execution (3 Terminals)](#manual-execution-3-terminals)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Configuration](#configuration)
- [Performance Metrics](#performance-metrics)
- [Troubleshooting](#troubleshooting)
- [Technical Details](#technical-details)
- [Contributing](#contributing)
- [References](#references)
- [License](#license)

---

## Overview

This project demonstrates a quantum-resistant DTLS 1.3 implementation running on a simulated RISC-V processor in a bare-metal environment. It addresses the critical challenge of securing IoT devices against future quantum computing threats while operating under severe resource constraints.

**Key Achievement**: Successful mutual authentication and encrypted communication between a RISC-V IoT device and server using NIST-approved post-quantum cryptographic algorithms.

---

## Features

- ✅ **DTLS 1.3**: Latest datagram transport layer security protocol
- ✅ **Post-Quantum Cryptography**: NIST-approved algorithms
  - **ML-KEM (Kyber)**: Key Encapsulation Mechanism for key exchange
  - **Dilithium**: Digital signature scheme for authentication
- ✅ **Bare-Metal RISC-V**: No OS dependency, BIOS-level operation
- ✅ **Mutual Authentication**: Both client and server certificate verification
- ✅ **Resource Optimized**: Designed for constrained IoT devices
- ✅ **LiteX Simulation**: Hardware-accurate RISC-V VexRiscv simulation
- ✅ **Hybrid Mode**: Combines classical and PQC algorithms

---

## System Architecture

```
┌─────────────────────┐         ┌──────────────────┐         ┌─────────────────────┐
│                     │  UART   │                  │   UDP   │                     │
│  RISC-V Simulation  │◄───────►│  UART-UDP Bridge │◄───────►│   DTLS PQC Server   │
│  (LiteX+Verilator)  │  TCP    │   (Python)       │  4444   │   (Native Binary)   │
│                     │  1234   │                  │         │                     │
│  - Client Firmware  │         │  - Packet        │         │  - wolfSSL          │
│  - wolfSSL/wolfCrypt│         │    Forwarding    │         │  - PQC Algorithms   │
│  - PQC Algorithms   │         │  - Protocol      │         │  - Certificate      │
│  - DTLS 1.3 Client  │         │    Translation   │         │    Verification     │
└─────────────────────┘         └──────────────────┘         └─────────────────────┘
```

**Communication Flow**:
1. RISC-V firmware initiates DTLS handshake via UART
2. Bridge translates UART ↔ UDP packets
3. Server performs PQC operations and responds
4. Secure channel established with quantum-resistant cryptography

---

## Prerequisites

### Operating System
- **Recommended**: Ubuntu 20.04 LTS or later
- **Alternative**: Any Linux distribution with package manager

### Hardware Requirements
- **CPU**: x86_64 processor (2+ cores recommended)
- **RAM**: 4 GB minimum, 8 GB recommended
- **Storage**: 2 GB free space

### Required Skills
- Basic Linux command line
- Understanding of compilation process
- Network concepts (UDP, ports)

---

## Installation

### 1. System Dependencies

Install essential build tools and RISC-V toolchain:

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    gcc-riscv64-unknown-elf \
    binutils-riscv64-unknown-elf \
    libtool \
    autoconf \
    automake \
    python3 \
    python3-pip \
    git \
    wget \
    verilator
```

**Verification**:
```bash
riscv64-unknown-elf-gcc --version
# Expected: gcc (GCC) 10.x.x or later
```

### 2. Python Packages

Install LiteX framework and dependencies:

```bash
# Core packages
pip3 install --user meson ninja litex

# LiteX components
pip3 install --user git+https://github.com/litex-hub/pythondata-cpu-vexriscv.git
pip3 install --user git+https://github.com/litex-hub/pythondata-software-compiler_rt.git
pip3 install --user git+https://github.com/litex-hub/pythondata-software-picolibc.git
pip3 install --user git+https://github.com/litex-hub/pythondata-misc-tapcfg.git
```

**Add to PATH** (add to `~/.bashrc`):
```bash
export PATH="$HOME/.local/bin:$PATH"
```

**Verification**:
```bash
litex_sim --help
# Expected: LiteX simulation command help
```

### 3. wolfSSL with PQC Support

Clone and install wolfSSL with post-quantum cryptography:

```bash
# Clone wolfSSL
cd /usr/local/src
sudo git clone https://github.com/wolfSSL/wolfssl.git
sudo chown -R $USER:$USER wolfssl
cd -

# Build and install with PQC support
sudo WOLFSSL_DIR=/usr/local/src/wolfssl ./install_wolfssl.sh
```

**What this does**:
- Configures wolfSSL with DTLS 1.3 support
- Enables Dilithium signature algorithms
- Enables ML-KEM (Kyber) key exchange
- Installs to `/usr/local/lib` and `/usr/local/include`

**Build time**: 5-10 minutes

**Verification**:
```bash
ls /usr/local/include/wolfssl/
# Expected: Directory listing with wolfssl headers

sudo ldconfig -v 2>/dev/null | grep wolfssl
# Expected: libwolfssl.so.XX
```

### 4. Certificate Generation

Generate PQC certificates for mutual authentication:

```bash
./generate_pqc_certs.sh
```

**Generated files in** `pqc_certs/`:
- `ca-dilithium-cert.pem` - Certificate Authority
- `server-dilithium-cert.pem` - Server certificate
- `server-dilithium-key.pem` - Server private key
- `client-dilithium-cert.pem` - Client certificate
- `client-dilithium-key.pem` - Client private key

**Verification**:
```bash
ls -lh pqc_certs/
# Expected: 5 PEM files
```

---

## Building the Project

### Build RISC-V Firmware

Compile the bare-metal client firmware:

```bash
./build_firmware.sh
```

**Build Process**:
1. Compiles `boot/main.c` with embedded wolfSSL
2. Links with RISC-V libraries (picolibc, compiler_rt)
3. Generates three output formats

**Generated Files**:
- `boot.bin` - Raw binary (~420 KB)
- `boot.elf` - ELF executable with debug symbols
- `boot.fbi` - LiteX bootable image (used by simulator)

**Build Options** (modify in `boot/Makefile`):
```makefile
RISCV_ARCH = rv32ima    # RISC-V architecture
RISCV_ABI = ilp32       # ABI specification
RAM_SIZE = 0x06400000   # 100 MB RAM
```

**Verification**:
```bash
ls -lh boot.bin boot.elf boot.fbi
# Expected: All three files present, ~420 KB each

riscv64-unknown-elf-objdump -h boot.elf | head -20
# Expected: ELF section headers
```

**Troubleshooting Build Errors**:
```bash
# If wolfssl.h not found:
sudo ldconfig
export C_INCLUDE_PATH=/usr/local/include:$C_INCLUDE_PATH
export LIBRARY_PATH=/usr/local/lib:$LIBRARY_PATH

# Clean and rebuild:
cd boot && make clean && cd ..
./build_firmware.sh
```

### Build DTLS Server

Compile the native DTLS server:

```bash
cd dtls_server
make
cd ..
```

**Generated Binary**:
- `dtls_server/dtls_pqc_server` (~2.5 MB)

**Verification**:
```bash
ldd dtls_server/dtls_pqc_server
# Expected: Shows linked wolfSSL library

./dtls_server/dtls_pqc_server --help
# Expected: Usage information
```

---

## Running the Demo

### Quick Start (Automated)

Run the complete demonstration with a single command:

```bash
./run_demo.sh
```

**What Happens**:
1. ✓ Starts DTLS PQC Server (UDP port 4444)
2. ✓ Starts LiteX RISC-V Simulation (60-75s build time)
3. ✓ Starts UART-UDP Bridge (connects components)
4. ✓ Monitors handshake progress
5. ✓ Reports success or failure

**Expected Output**:
```
════════════════════════════════════════════════════════════════
  DTLS 1.3 Post-Quantum Cryptography Demo
════════════════════════════════════════════════════════════════

[+] Starting DTLS PQC Server...
[+] Starting LiteX RISC-V Simulation...
    Building simulation (this takes 60-75 seconds)...
[+] Starting UART-UDP Bridge...
[+] Monitoring handshake...

[Server] Received ClientHello
[Server] Sending ServerHello with ML-KEM parameters
[Server] Certificate verification in progress...
[Server] ✓ Client certificate verified
[Server] Computing ML-KEM shared secret...
[Server] ✓ Session keys derived
[Server] DTLS 1.3 handshake complete

✓✓✓ SUCCESS! DTLS 1.3 Post-Quantum Handshake Completed ✓✓✓

Cryptographic Details:
  • Key Exchange: ML-KEM-768 (Kyber)
  • Signatures: Dilithium3
  • Cipher Suite: TLS_AES_128_GCM_SHA256
  • Authentication: Mutual (Client + Server)

Total Time: 98 seconds
```

**Runtime**: 90-120 seconds
**Logs Saved To**: `logs/` directory

### Manual Execution (3 Terminals)

For debugging or demonstration, run components separately:

#### Terminal 1: DTLS Server

```bash
cd dtls_server
./dtls_pqc_server
```

**Expected Output**:
```
═══════════════════════════════════════════════════════
  DTLS 1.3 Server with Post-Quantum Cryptography
═══════════════════════════════════════════════════════

Configuration:
  • Port: 4444 (UDP)
  • Certificates: pqc_certs/
  • Algorithms: Dilithium + ML-KEM

[Server] wolfSSL initialized
[Server] Certificates loaded
[Server] Listening on UDP port 4444...
```

**Leave this running** and proceed to Terminal 2.

#### Terminal 2: LiteX RISC-V Simulation

Wait 10 seconds after starting server, then:

```bash
litex_sim \
    --csr-json csr.json \
    --cpu-type=vexriscv \
    --cpu-variant=full \
    --integrated-main-ram-size=0x06400000 \
    --ram-init=boot.fbi
```

**Expected Output** (first 60-75 seconds):
```
[INFO] Building LiteX simulation...
[INFO] Compiling Verilator model...
...
[INFO] Simulation running at 10 MHz
```

**Expected Output** (after boot):
```
        __   _ __      _  __
       / /  (_) /____ | |/_/
      / /__/ / __/ -_)>  
     /____/_/\__/\__/_/|_|
   Build your hardware, easily!

 (c) Copyright 2012-2024 Enjoy-Digital
 (c) Copyright 2007-2015 M-Labs

BIOS CRC passed (xxxxxxxx)

--=============== SoC ==================--
CPU:            VexRiscv @ 10MHz
ROM:            32KB
SRAM:           4KB
MAIN-RAM:       100MB

[Client] Starting DTLS client...
```

**Leave this running** and proceed to Terminal 3.

#### Terminal 3: UART-UDP Bridge

Wait 75 seconds after starting simulation, then:

```bash
python3 uart_udp_bridge.py \
    --tcp-host 127.0.0.1 \
    --tcp-port 1234 \
    --udp-local-ip 127.0.0.1 \
    --udp-remote-ip 127.0.0.1 \
    --udp-remote-port 4444
```

**Expected Output**:
```
════════════════════════════════════════════════════════
  UART-UDP Bridge
════════════════════════════════════════════════════════

Configuration:
  UART (TCP): 127.0.0.1:1234
  UDP Remote: 127.0.0.1:4444

[Bridge] Connecting to UART...
[Bridge] ✓ Connected
[Bridge] Starting packet forwarding...
[Bridge] Forwarding UART → UDP (245 bytes)
[Bridge] Forwarding UDP → UART (312 bytes)
```

**Watch Terminal 1** for handshake completion!

---

## Project Structure

```
pqc-dtls-riscv/
├── README.md                          # This file
├── QUICKSTART.txt                     # Quick reference guide
├── LICENSE                            # MIT License
│
├── Execution Scripts
│   ├── run_demo.sh                    # ⭐ Main automated demo
│   ├── build_firmware.sh              # Build RISC-V firmware
│   ├── build_dtls_firmware.sh         # Alternative build script
│   ├── install_wolfssl.sh             # Install wolfSSL
│   ├── generate_pqc_certs.sh          # Generate certificates
│   ├── cleanup.sh                     # Clean build artifacts
│   ├── test_pipeline.sh               # Test without DTLS
│   └── simulate_handshake.py          # Handshake simulator
│
├── Core Components
│   ├── boot/
│   │   ├── main.c                     # RISC-V client firmware
│   │   ├── Makefile                   # Firmware build system
│   │   └── linker.ld                  # Linker script
│   │
│   ├── dtls_server/
│   │   ├── dtls_pqc_server.c          # DTLS server implementation
│   │   └── Makefile                   # Server build system
│   │
│   └── uart_udp_bridge.py             # UART↔UDP protocol bridge
│
├── Configuration
│   ├── csr.json                       # LiteX CSR configuration
│   └── wolfssl_config.h               # wolfSSL compile options
│
├── Generated Files (after build)
│   ├── boot.bin                       # Raw firmware binary
│   ├── boot.elf                       # ELF executable
│   ├── boot.fbi                       # LiteX bootable image
│   └── pqc_certs/                     # PQC certificates
│       ├── ca-dilithium-cert.pem
│       ├── server-dilithium-cert.pem
│       ├── server-dilithium-key.pem
│       ├── client-dilithium-cert.pem
│       └── client-dilithium-key.pem
│
├── Testing Utilities
│   └── test_udp_server.py             # Simple UDP echo server
│
└── Documentation
    └── docs/                          # Additional technical docs
```

### Directory Purposes

- **`boot/`**: RISC-V bare-metal firmware source code and build system
- **`dtls_server/`**: Native DTLS server with PQC support
- **`pqc_certs/`**: Self-signed certificates for demonstration
- **`logs/`**: Runtime logs from all components (auto-generated)

---

## Testing

### Test Communication Pipeline (No DTLS)

Verify the UART-UDP bridge works correctly:

```bash
./test_pipeline.sh
```

This runs a simple echo test without cryptography.

**Expected Output**:
```
Testing communication pipeline...
✓ UART → UDP forwarding works
✓ UDP → UART forwarding works
✓ Round-trip latency: 12ms
```

### Manual Testing Tools

#### UDP Echo Server
```bash
python3 test_udp_server.py --port 4444
```

#### Handshake Simulation
```bash
python3 simulate_handshake.py --verbose
```

---

## Configuration

### Firmware Configuration (`boot/main.c`)

```c
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4444
#define CERT_FILE "pqc_certs/client-dilithium-cert.pem"
#define KEY_FILE "pqc_certs/client-dilithium-key.pem"
```

### wolfSSL Configuration (`wolfssl_config.h`)

Key options:
```c
#define WOLFSSL_DTLS13                 // Enable DTLS 1.3
#define HAVE_DILITHIUM                 // Dilithium signatures
#define WOLFSSL_DILITHIUM_LEVEL 3      // Security level (2/3/5)
#define HAVE_KYBER                     // ML-KEM key exchange
#define WOLFSSL_KYBER768               // ML-KEM-768
#define WOLFSSL_AES_128                // AES-128-GCM
```

### LiteX Configuration (`csr.json`)

Generated automatically, contains:
- Memory map (ROM, SRAM, MAIN-RAM)
- CSR (Control and Status Register) addresses
- Peripheral configurations

### Security Levels

Choose Dilithium level based on security requirements:

| Level | Classical Security | Key Size | Signature Size |
|-------|-------------------|----------|----------------|
| 2     | 128-bit (AES-128) | 2.5 KB   | 2.4 KB         |
| 3     | 192-bit (AES-192) | 4.0 KB   | 3.3 KB         |
| 5     | 256-bit (AES-256) | 4.9 KB   | 4.6 KB         |

**Default**: Dilithium3 (NIST Level 3)

---

## Performance Metrics

### Simulation Environment
- **CPU**: RISC-V VexRiscv @ 10 MHz (simulated)
- **RAM**: 100 MB
- **Platform**: LiteX + Verilator

### Handshake Performance

| Operation | Simulated Time | Real Hardware (Est.) |
|-----------|----------------|----------------------|
| Dilithium Sign | 20-40 ms | 2-4 ms @ 100MHz |
| Dilithium Verify | 15-30 ms | 1.5-3 ms @ 100MHz |
| ML-KEM Encapsulate | 10-20 ms | 1-2 ms @ 100MHz |
| ML-KEM Decapsulate | 10-20 ms | 1-2 ms @ 100MHz |
| **Full Handshake** | **30-60 seconds** | **<1 second @ 100MHz** |

### Memory Usage

| Component | Size |
|-----------|------|
| Firmware Code | ~400 KB |
| wolfSSL Library | ~350 KB |
| PQC Algorithms | ~100 KB |
| Crypto Buffers | ~100 KB |
| **Total ROM** | **~420 KB** |
| **Runtime RAM** | **~2 MB** |

### Throughput

- **Handshake Overhead**: ~245 KB (client → server)
- **Application Data**: ~2 KB/s in simulation
- **Cipher**: AES-128-GCM (hardware accelerated on real devices)

---

## Troubleshooting

### Build Errors

#### Error: `wolfssl/ssl.h: No such file or directory`

**Solution**:
```bash
sudo ldconfig
ls /usr/local/include/wolfssl/
# If empty, reinstall:
sudo ./install_wolfssl.sh
```

#### Error: `riscv64-unknown-elf-gcc: command not found`

**Solution**:
```bash
sudo apt-get install gcc-riscv64-unknown-elf binutils-riscv64-unknown-elf
riscv64-unknown-elf-gcc --version
```

#### Error: `litex_sim: command not found`

**Solution**:
```bash
pip3 install --user litex
export PATH="$HOME/.local/bin:$PATH"
```

### Runtime Errors

#### Error: Handshake Timeout

**Diagnosis**:
```bash
ps aux | grep -E "litex_sim|dtls_pqc_server|uart_udp_bridge"
```

**Solution**:
1. Ensure all 3 components are running
2. Check logs: `tail -f logs/*.log`
3. Verify port 4444 is free: `sudo netstat -tulpn | grep 4444`
4. Increase timeout in `run_demo.sh`

#### Error: Bridge Connection Failed

**Solution**:
1. Wait 75 seconds for simulation to fully boot
2. Check simulation log: `tail -f logs/litex_sim.log`
3. Verify TCP port 1234 is available

#### Error: Certificate Verification Failed

**Solution**:
```bash
# Regenerate certificates
./generate_pqc_certs.sh

# Check certificates exist
ls -lh pqc_certs/*.pem
```

### Debugging Commands

```bash
# View live logs
tail -f logs/dtls_server.log      # Server activity
tail -f logs/litex_sim.log        # RISC-V simulation
tail -f logs/uart_bridge.log      # Bridge packets

# Check process status
ps aux | grep -E "litex|dtls|bridge"

# Check ports
sudo netstat -tulpn | grep -E "1234|4444"

# Stop all processes
pkill -f "litex_sim|dtls_pqc_server|uart_udp_bridge"

# Clean rebuild
./cleanup.sh
./build_firmware.sh
cd dtls_server && make clean && make && cd ..
./run_demo.sh
```

---

## Technical Details

### Cryptographic Algorithms

#### ML-KEM (Module Lattice Key Encapsulation Mechanism)
- **Type**: Key Exchange
- **Variant**: ML-KEM-768 (NIST Level 3)
- **Public Key**: 1,184 bytes
- **Ciphertext**: 1,088 bytes
- **Shared Secret**: 32 bytes
- **Security**: ~192-bit classical equivalent

#### Dilithium (Lattice-based Digital Signature)
- **Type**: Authentication
- **Variant**: Dilithium3 (NIST Level 3)
- **Public Key**: ~1,952 bytes
- **Signature**: ~3,293 bytes
- **Security**: ~192-bit classical equivalent

#### AES-128-GCM
- **Type**: Symmetric Encryption
- **Key Size**: 128 bits
- **Mode**: Galois/Counter Mode (authenticated encryption)

### DTLS 1.3 Handshake Flow

```
Client (RISC-V)                          Server
      |                                      |
      |--- ClientHello ------------------>  |
      |    (ML-KEM public key)              |
      |                                      |
      |<-- ServerHello -------------------  |
      |    (ML-KEM ciphertext)              |
      |<-- EncryptedExtensions -----------  |
      |<-- Certificate -------------------  |
      |    (Dilithium public key)           |
      |<-- CertificateVerify -------------  |
      |    (Dilithium signature)            |
      |<-- Finished ----------------------  |
      |                                      |
      |--- Certificate ------------------>  |
      |    (Dilithium public key)           |
      |--- CertificateVerify ------------->  |
      |    (Dilithium signature)            |
      |--- Finished ---------------------->  |
      |                                      |
      |<=== Encrypted Application Data ===>  |
```

### Memory Map (RISC-V)

```
0x00000000 - 0x00007FFF : ROM (32 KB)
0x00008000 - 0x00008FFF : SRAM (4 KB)
0x40000000 - 0x465FFFFF : MAIN-RAM (100 MB)
0x82000000 - 0x82001FFF : CSR (peripherals)
```

### Compiler Flags

```makefile
CFLAGS = -march=rv32ima -mabi=ilp32 \
         -O2 -g \
         -ffunction-sections -fdata-sections \
         -nostdlib -nostartfiles \
         -DWOLFSSL_USER_SETTINGS

LDFLAGS = -Wl,--gc-sections \
          -Wl,-T,linker.ld \
          -Wl,--no-relax
```

---

## Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Commit** your changes: `git commit -m 'Add amazing feature'`
4. **Push** to the branch: `git push origin feature/amazing-feature`
5. **Open** a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/pqc-dtls-riscv.git
cd pqc-dtls-riscv

# Set up development environment
./install_wolfssl.sh
./build_firmware.sh

# Make changes and test
./run_demo.sh
```

---

## References

### Standards & Specifications
- [RFC 9147: DTLS 1.3](https://datatracker.ietf.org/doc/rfc9147/)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203: ML-KEM Standard](https://csrc.nist.gov/pubs/fips/203/final)

### Libraries & Frameworks
- [wolfSSL Documentation](https://www.wolfssl.com/documentation/)
- [LiteX Framework](https://github.com/enjoy-digital/litex)
- [VexRiscv CPU](https://github.com/SpinalHDL/VexRiscv)

### Post-Quantum Algorithms
- [Dilithium Specification](https://pq-crystals.org/dilithium/)
- [Kyber/ML-KEM Specification](https://pq-crystals.org/kyber/)

### Academic Papers
- "Post-Quantum Cryptography for IoT Devices" - IEEE IoT Journal
- "Efficient Implementation of Lattice-based Cryptography on RISC-V" - IACR ePrint

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 PQC-DTLS RISC-V Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Acknowledgments

- **QTrino Labs** - Problem statement and technical guidance
- **Inter IIT Tech Meet 14.0** - Competition framework
- **wolfSSL Inc.** - SSL/TLS library with PQC support
- **Enjoy-Digital** - LiteX SoC framework
- **NIST** - Post-Quantum Cryptography standardization

---

## Support

For issues, questions, or contributions:

- **Issues**: [GitHub Issues](https://github.com/YOUR_USERNAME/pqc-dtls-riscv/issues)
- **Discussions**: [GitHub Discussions](https://github.com/YOUR_USERNAME/pqc-dtls-riscv/discussions)
- **Email**: your.email@example.com

---

**Built with ❤️ for the Post-Quantum Era**