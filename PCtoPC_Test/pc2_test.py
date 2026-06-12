#!/usr/bin/env python3
"""
PC2 (Windows) - FPGA Encryption Gateway Test Script

Setup (Windows):
  - IP: 192.168.1.129 / 255.255.255.0
  - CMD (admin): arp -s 192.168.1.128 02-00-00-00-00-01
  - Install Python: python.org

Run:
  python pc2_test.py 1   # Listen for encrypted packets
  python pc2_test.py 2   # Send encrypted packets (decrypt test)
  python pc2_test.py 3   # Full verification test
"""

import socket
import sys
import time

PC2_IP    = "192.168.1.129"
FPGA_IP   = "192.168.1.128"
UDP_PORT  = 1234

FIXED_KEY   = bytes([0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
                     0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00])
FIXED_AD    = bytes([0x00, 0xFF, 0xEE, 0xDD])

LFSR_SEED = 0xDEADBEEF_12345678_ABCDEF01_98765432
LFSR_POLY = 0x00000000_00000004_20000000_00000027
MASK_128  = (1 << 128) - 1

try:
    from ascon import ascon_encrypt, ascon_decrypt
    HAS_ASCON = True
    print("[OK] pyascon loaded - verification enabled")
except ImportError:
    HAS_ASCON = False
    print("[WARN] pyascon not found - verification disabled")
    print("       Download ascon.py from github.com/rprimas/ascon-verilog")


def lfsr_advance(nonce_int):
    msb = (nonce_int >> 127) & 1
    shifted = (nonce_int << 1) & MASK_128
    if msb:
        shifted ^= LFSR_POLY
    return shifted


def nonce_int_to_bytes(nonce_int):
    result = []
    for i in range(16):
        result.append((nonce_int >> (i * 8)) & 0xFF)
    return bytes(result)


def parse_encrypted_packet(data):
    """Parse: nonce(16) + AD(4) + CT(N) + tag(16)"""
    if len(data) < 36:
        print(f"  ERROR: Packet too short ({len(data)} bytes)")
        return None

    nonce = data[0:16]
    ad    = data[16:20]
    ct    = data[20:-16]
    tag   = data[-16:]

    print(f"  Total:  {len(data)} bytes")
    print(f"  Nonce:  {nonce.hex()}")
    print(f"  AD:     {ad.hex()}")
    print(f"  CT:     {ct.hex()} ({len(ct)} bytes)")
    print(f"  Tag:    {tag.hex()}")

    return nonce, ad, ct, tag


def arp_warmup():
    """Send dummy packet to FPGA to trigger ARP resolution."""
    print("  [ARP] Sending warmup packet to FPGA...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(b"\x00", (FPGA_IP, UDP_PORT))
    sock.close()
    time.sleep(2)
    print("  [ARP] Ready.\n")


# ============================================================
# Mode 1: Listen
# ============================================================
def mode_listen():
    """Listen for encrypted packets from FPGA."""
    print(f"\n{'='*60}")
    print(f"LISTEN MODE - Waiting for encrypted packets")
    print(f"Binding to {PC2_IP}:{UDP_PORT}")
    print(f"Press Ctrl+C to stop")
    print(f"{'='*60}\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((PC2_IP, UDP_PORT))

    pkt_count = 0
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            pkt_count += 1
            print(f"\n--- Packet #{pkt_count} from {addr} ---")
            print(f"  Raw hex: {data.hex()}")
            result = parse_encrypted_packet(data)

            if HAS_ASCON and result:
                nonce, ad, ct, tag = result
                try:
                    pt = ascon_decrypt(FIXED_KEY, nonce, ad, ct + tag,
                                      variant="Ascon-AEAD128")
                    if pt is not None:
                        pt = bytes(pt)
                        print(f"  Decrypted: {pt.hex()}")
                        try:
                            print(f"  Text:      {pt.decode('utf-8', errors='replace')}")
                        except:
                            pass
                        print(f"  >>> DECRYPT OK <<<")
                    else:
                        print(f"  >>> AUTH FAILED <<<")
                except Exception as e:
                    print(f"  Decrypt error: {e}")

    except KeyboardInterrupt:
        print(f"\nStopped. Received {pkt_count} packets.")
    finally:
        sock.close()


# ============================================================
# Mode 2: Interactive send (ARP once, send many)
# ============================================================
def mode_send():
    """Send encrypted packets to FPGA. ARP warmup once, then interactive loop."""
    if not HAS_ASCON:
        print("ERROR: pyascon required. Download ascon.py")
        return

    print(f"\n{'='*60}")
    print(f"SEND MODE - Decrypt path test")
    print(f"Target: {FPGA_IP}:{UDP_PORT}")
    print(f"PC1 should listen on 10.0.0.2:1234")
    print(f"{'='*60}\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # ARP warmup — sadece 1 kere
    print("  [ARP] Sending warmup packet...")
    sock.sendto(b"\x00", (FPGA_IP, UDP_PORT))
    time.sleep(2)
    print("  [ARP] Ready.\n")

    nonce_int = LFSR_SEED
    pkt_count = 0
    # Warmup nonce'u ilerlet
    nonce_int = lfsr_advance(nonce_int)

    print("Type plaintext and press Enter to send. Type 'q' to quit.\n")

    while True:
        try:
            text = input("Plaintext> ")
        except (EOFError, KeyboardInterrupt):
            break

        if text.lower() == 'q':
            break

        if not text:
            continue

        plaintext = text.encode('utf-8')
        current_nonce = nonce_int_to_bytes(nonce_int)

        ref = ascon_encrypt(FIXED_KEY, current_nonce, FIXED_AD, plaintext,
                           variant="Ascon-AEAD128")
        if isinstance(ref, tuple):
            ct, tag = bytes(ref[0]), bytes(ref[1])
        else:
            ct  = ref[:len(plaintext)]
            tag = ref[len(plaintext):]

        packet = current_nonce + FIXED_AD + ct + tag

        sock.sendto(packet, (FPGA_IP, UDP_PORT))
        pkt_count += 1

        print(f"  [{pkt_count}] Sent '{text}' ({len(packet)} bytes encrypted)")
        parse_encrypted_packet(packet)
        print()

        nonce_int = lfsr_advance(nonce_int)

    sock.close()
    print(f"\nDone! {pkt_count} packets sent.")


# ============================================================
# Mode 3: Full verification test
# ============================================================
def mode_full_test():
    """Listen and verify against known plaintexts."""
    print(f"\n{'='*60}")
    print(f"FULL TEST MODE")
    print(f"Listening on {PC2_IP}:{UDP_PORT}")
    print(f"Send from PC1: python3 pc1_test.py 1")
    print(f"{'='*60}\n")

    test_vectors = [
        b"A",
        b"ABCD",
        b"hello",
        bytes(range(8)),
        b"Hello, ASCON!",
    ]

    print("Expected plaintexts (PC1 sends these in order):")
    for i, pt in enumerate(test_vectors):
        print(f"  {i+1}. {pt.hex()} ({pt})")
    print()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(60)
    sock.bind((PC2_IP, UDP_PORT))

    passed = 0
    total = 0

    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                print("Timeout")
                break

            total += 1
            print(f"\n--- Packet #{total} from {addr} ---")

            result = parse_encrypted_packet(data)
            if result and HAS_ASCON:
                nonce, ad, ct, tag = result
                try:
                    pt = ascon_decrypt(FIXED_KEY, nonce, ad, ct + tag,
                                      variant="Ascon-AEAD128")
                    if pt is not None:
                        pt = bytes(pt)
                        print(f"  Decrypted: {pt.hex()}")
                        try:
                            print(f"  Text:      {pt.decode('utf-8', errors='replace')}")
                        except:
                            pass

                        if total <= len(test_vectors) and pt == test_vectors[total - 1]:
                            print(f"  >>> PASS <<<")
                            passed += 1
                        elif total <= len(test_vectors):
                            print(f"  >>> FAIL — expected {test_vectors[total-1]} <<<")
                        else:
                            print(f"  >>> DECRYPT OK <<<")
                    else:
                        print(f"  >>> AUTH FAILED <<<")
                except Exception as e:
                    print(f"  Decrypt error: {e}")

    except KeyboardInterrupt:
        pass
    finally:
        sock.close()

    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} verified")
    print(f"{'='*60}")


# ============================================================
# Main
# ============================================================
if __name__ == "__main__":
    print("FPGA Encryption Gateway - PC2 Test Script")
    print(f"PC2: {PC2_IP}, FPGA: {FPGA_IP}, Port: {UDP_PORT}\n")
    print("  1. Listen  - Wait for encrypted packets")
    print("  2. Send    - Interactive send (decrypt test)")
    print("  3. Test    - Full verification with known plaintexts")
    print()

    choice = sys.argv[1] if len(sys.argv) > 1 else input("Select (1/2/3): ").strip()

    if choice == "1":
        mode_listen()
    elif choice == "2":
        mode_send()
    elif choice == "3":
        mode_full_test()
    else:
        print("Invalid choice")
