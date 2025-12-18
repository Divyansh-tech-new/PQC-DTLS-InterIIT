#!/usr/bin/env python3
"""
Simulate DTLS 1.3 Handshake with Dilithium Signing
Shows step-by-step what happens during mutual authentication
"""

import time
import hashlib

def print_box(text, width=78):
    """Print text in a box"""
    print("┌" + "─" * width + "┐")
    for line in text.split('\n'):
        print("│ " + line.ljust(width-1) + "│")
    print("└" + "─" * width + "┘")

def simulate_signing(entity, message, key_size=2560):
    """Simulate Dilithium signing"""
    print(f"\n  [{entity}] Signing with Dilithium Level 2...")
    print(f"    • Using private key ({key_size} bytes)")
    print(f"    • Message to sign: '{message}'")
    
    # Simulate hashing
    time.sleep(0.1)
    msg_hash = hashlib.sha256(message.encode()).hexdigest()[:16]
    print(f"    • Message hash: {msg_hash}...")
    
    # Simulate signing
    time.sleep(0.2)
    signature = hashlib.sha256(f"{message}{key_size}".encode()).hexdigest()[:32]
    print(f"    • Generated signature (~2420 bytes): {signature}...")
    print(f"    ✓ Signing complete!")
    
    return signature

def simulate_verification(entity, signature, message, pub_key_size=1312):
    """Simulate Dilithium verification"""
    print(f"\n  [{entity}] Verifying signature with Dilithium Level 2...")
    print(f"    • Using public key ({pub_key_size} bytes)")
    print(f"    • Signature to verify: {signature[:32]}...")
    
    # Simulate verification
    time.sleep(0.15)
    print(f"    • Computing message hash...")
    time.sleep(0.1)
    print(f"    • Checking signature validity...")
    time.sleep(0.1)
    print(f"    ✓ Signature VALID - Identity confirmed!")
    
    return True

def main():
    print("\n" + "="*80)
    print_box("PQC-DTLS 1.3 Mutual Authentication Demo\nShowing Dilithium Signing in Action")
    print("="*80 + "\n")
    
    print("Scenario: RISC-V Client ←→ Linux Server")
    print("Protocol: DTLS 1.3 with ML-KEM-512 + Dilithium Level 2")
    print()
    input("Press Enter to start handshake simulation...")
    
    # Phase 1: Initial exchange
    print("\n" + "─"*80)
    print("PHASE 1: Initial Key Exchange (ML-KEM-512)")
    print("─"*80)
    
    print("\n[Client → Server] ClientHello")
    print("  • Supported groups: ML-KEM-512 (Kyber)")
    print("  • Signature algorithms: Dilithium Level 2, 3, 5")
    time.sleep(0.3)
    
    print("\n[Server → Client] ServerHello")
    print("  • Selected group: ML-KEM-512")
    print("  • Selected signature: Dilithium Level 2")
    time.sleep(0.3)
    
    # Phase 2: Server authentication
    print("\n" + "─"*80)
    print("PHASE 2: Server Authentication (Dilithium Signing)")
    print("─"*80)
    
    print("\n[Server → Client] Certificate")
    print("  • Server certificate with Dilithium public key")
    print("  • Certificate size: 1312 bytes (public key)")
    time.sleep(0.3)
    
    # Server signs
    server_message = "DTLS 1.3 Server Certificate Verify"
    server_sig = simulate_signing("Server", server_message)
    
    print("\n[Server → Client] CertificateVerify")
    print(f"  • Sending Dilithium signature to prove identity")
    time.sleep(0.3)
    
    # Client verifies server
    simulate_verification("Client", server_sig, server_message)
    
    print("\n  ✓✓✓ CLIENT AUTHENTICATED SERVER ✓✓✓")
    time.sleep(0.5)
    
    # Phase 3: Client authentication
    print("\n" + "─"*80)
    print("PHASE 3: Client Authentication (Dilithium Signing)")
    print("─"*80)
    
    print("\n[Client → Server] Certificate")
    print("  • Client certificate with Dilithium public key")
    print("  • Certificate size: 1312 bytes (public key)")
    time.sleep(0.3)
    
    # Client signs
    client_message = "DTLS 1.3 Client Certificate Verify"
    client_sig = simulate_signing("Client", client_message)
    
    print("\n[Client → Server] CertificateVerify")
    print(f"  • Sending Dilithium signature to prove identity")
    time.sleep(0.3)
    
    # Server verifies client
    simulate_verification("Server", client_sig, client_message)
    
    print("\n  ✓✓✓ SERVER AUTHENTICATED CLIENT ✓✓✓")
    time.sleep(0.5)
    
    # Phase 4: Completion
    print("\n" + "─"*80)
    print("PHASE 4: Handshake Completion")
    print("─"*80)
    
    print("\n[Client ↔ Server] Finished messages")
    print("  • Both sides exchange encrypted Finished messages")
    print("  • Handshake transcript verified")
    time.sleep(0.3)
    
    print("\n" + "="*80)
    print_box("✓ MUTUAL AUTHENTICATION COMPLETE!\n\n" +
              "Both sides verified using Dilithium Level 2 signatures:\n" +
              "  • Server signed and client verified\n" +
              "  • Client signed and server verified\n\n" +
              "Secure channel established with:\n" +
              "  • Key Exchange: ML-KEM-512 (post-quantum KEM)\n" +
              "  • Authentication: Dilithium Level 2 (post-quantum signature)\n" +
              "  • Encryption: AES-128-GCM or ChaCha20-Poly1305")
    print("="*80)
    
    # Summary
    print("\n" + "─"*80)
    print("SIGNATURE OPERATIONS SUMMARY")
    print("─"*80)
    
    print("\nServer Operations:")
    print("  1. Signed its certificate → Proved it owns server private key")
    print("  2. Verified client signature → Confirmed client identity")
    
    print("\nClient Operations:")
    print("  1. Verified server signature → Confirmed server identity")
    print("  2. Signed its certificate → Proved it owns client private key")
    
    print("\nDilithium Parameters Used:")
    print("  • Algorithm: ML-DSA-44 (Dilithium Level 2)")
    print("  • Public key size: 1,312 bytes")
    print("  • Private key size: 2,560 bytes")
    print("  • Signature size: ~2,420 bytes")
    print("  • Security level: NIST Level 2 (≈AES-128)")
    
    print("\n" + "="*80)
    print("This is exactly what happens in your DTLS 1.3 implementation!")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
