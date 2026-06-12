#!/usr/bin/env python3
"""
PC1 (Linux) - FPGA Encryption Gateway Test Script

Setup:
  sudo ip addr add 10.0.0.2/24 dev enp45s0
  sudo ip link set enp45s0 up
  sudo arp -s 10.0.0.1 02:00:00:00:00:00 -i enp45s0

Run:
  python3 pc1_test.py 1   # Send plaintext (encrypt test)
  python3 pc1_test.py 2   # Listen for decrypted data (decrypt test)
"""

import socket
import sys
import time

PC1_IP   = "10.0.0.2"
FPGA_IP  = "10.0.0.1"
UDP_PORT = 1234


def arp_warmup(sock):
    """Send dummy packet to trigger ARP resolution, then wait."""
    print("  [ARP] Sending warmup packet...")
    sock.sendto(b"\x00", (FPGA_IP, UDP_PORT))
    time.sleep(2)
    print("  [ARP] Ready.\n")


def mode_send():
    """Send plaintext packets to FPGA ENET0"""
    print(f"\nSending plaintext to {FPGA_IP}:{UDP_PORT}")
    print("PC2 should receive encrypted version on 192.168.1.129:1234\n")

    tests = [
        b"A",
        b"ABCD",
        b"hello",
        bytes(range(8)),
        b"Hello, ASCON!",
    ]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # ARP warmup
    arp_warmup(sock)

    for i, pt in enumerate(tests):
        sock.sendto(pt, (FPGA_IP, UDP_PORT))
        print(f"  [{i+1}/{len(tests)}] Sent: {pt} ({pt.hex()})")
        time.sleep(0.5)

    sock.close()
    print(f"\nDone! {len(tests)} packets sent.")


def mode_listen():
    """Listen for decrypted plaintext from FPGA ENET0"""
    print(f"\nListening on {PC1_IP}:{UDP_PORT} for decrypted packets...")
    print("Send encrypted data from PC2 to FPGA ENET1\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(60)
    sock.bind((PC1_IP, UDP_PORT))

    pkt_count = 0
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            pkt_count += 1
            print(f"--- Packet #{pkt_count} from {addr} ---")
            print(f"  Hex:  {data.hex()}")
            try:
                print(f"  Text: {data.decode('utf-8', errors='replace')}")
            except:
                pass
            print()
    except socket.timeout:
        print("Timeout - no more packets")
    except KeyboardInterrupt:
        print("Stopped")
    finally:
        sock.close()
        print(f"Received {pkt_count} packets total.")


if __name__ == "__main__":
    print("PC1 Test Script - FPGA Encryption Gateway")
    print(f"PC1: {PC1_IP}, FPGA ENET0: {FPGA_IP}, Port: {UDP_PORT}\n")
    print("  1. Send plaintext to FPGA (encrypt test)")
    print("  2. Listen for decrypted data (decrypt test)")

    choice = sys.argv[1] if len(sys.argv) > 1 else input("\nSelect (1/2): ").strip()

    if choice == "1":
        mode_send()
    elif choice == "2":
        mode_listen()
