#!/usr/bin/env python3
"""
ASCON-AEAD128 FPGA UDP Test
Sends plaintext, receives nonce+AD+ciphertext+tag, verifies.
"""

import socket
import sys
import os

# Add ascon-verilog repo path for SP 800-232 reference
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fpga", "rtl", "ascon-verilog"))
from ascon import ascon_encrypt

FPGA_IP   = "192.168.1.128"
FPGA_PORT = 1234
LOCAL_IP  = "192.168.1.100"
TIMEOUT   = 5.0

# Must match RTL localparam values (little-endian byte order)
# RTL: FIXED_KEY = 128'h000102030405060708090A0B0C0D0E0F
# Wire: KEY[7:0]=0x0F, KEY[15:8]=0x0E, ...
FIXED_KEY = bytes([0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
                   0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00])

# RTL: FIXED_NONCE = 128'h0F0E0D0C0B0A09080706050403020100
# Wire: NONCE[7:0]=0x00, ...
FIXED_NONCE = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])

# RTL: FIXED_AD = 128'h000000000000000000000000DDEEFF00
# Wire: AD[7:0]=0x00, AD[15:8]=0xFF, AD[23:16]=0xEE, AD[31:24]=0xDD
FIXED_AD = bytes([0x00, 0xFF, 0xEE, 0xDD])


def send_and_receive(plaintext):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    sock.bind((LOCAL_IP, 0))
    sock.sendto(plaintext, (FPGA_IP, FPGA_PORT))
    try:
        data, addr = sock.recvfrom(4096)
        return data
    except socket.timeout:
        return None
    finally:
        sock.close()


def test(plaintext, name):
    print(f"\n{'='*60}")
    print(f"TEST: {name} ({len(plaintext)} bytes)")
    print(f"{'='*60}")
    print(f"  Sent:     {plaintext.hex()}")

    response = send_and_receive(plaintext)
    if response is None:
        print("  ERROR: No response (timeout)")
        return False

    print(f"  Received: {response.hex()} ({len(response)} bytes)")

    # Parse: nonce(16) + AD(4) + CT(N) + TAG(16)
    expected_len = 16 + 4 + len(plaintext) + 16
    if len(response) != expected_len:
        print(f"  ERROR: Expected {expected_len} bytes, got {len(response)}")
        return False

    nonce = response[0:16]
    ad    = response[16:20]
    ct    = response[20:20+len(plaintext)]
    tag   = response[20+len(plaintext):20+len(plaintext)+16]

    print(f"  Nonce:    {nonce.hex()}")
    print(f"  AD:       {ad.hex()}")
    print(f"  CT:       {ct.hex()}")
    print(f"  Tag:      {tag.hex()}")

    # Verify nonce and AD
    if nonce != FIXED_NONCE:
        print(f"  FAIL: Nonce mismatch! Expected {FIXED_NONCE.hex()}")
        return False
    if ad != FIXED_AD:
        print(f"  FAIL: AD mismatch! Expected {FIXED_AD.hex()}")
        return False

    # pyascon reference (SP 800-232)
    ref = ascon_encrypt(FIXED_KEY, FIXED_NONCE, FIXED_AD, plaintext, variant="Ascon-AEAD128")
    if isinstance(ref, tuple):
        ref_ct, ref_tag = bytes(ref[0]), bytes(ref[1])
    else:
        ref_ct  = ref[:len(plaintext)]
        ref_tag = ref[len(plaintext):]

    print(f"  Ref CT:   {ref_ct.hex()}")
    print(f"  Ref Tag:  {ref_tag.hex()}")

    if ct == ref_ct and tag == ref_tag:
        print(f"  >>> PASS <<<")
        return True
    else:
        print(f"  >>> FAIL <<<")
        if ct != ref_ct:
            for i in range(len(ct)):
                if i < len(ref_ct) and ct[i] != ref_ct[i]:
                    print(f"    CT byte {i}: expected 0x{ref_ct[i]:02x}, got 0x{ct[i]:02x}")
        if tag != ref_tag:
            print(f"    Tag mismatch")
        return False


if __name__ == "__main__":
    print("ASCON-AEAD128 FPGA UDP Encryption Test")
    print(f"Target: {FPGA_IP}:{FPGA_PORT}")
    print(f"Key:    {FIXED_KEY.hex()}")
    print(f"Nonce:  {FIXED_NONCE.hex()}")
    print(f"AD:     {FIXED_AD.hex()}")

    tests = [
        (b"A",              "1-byte"),
        (b"ABCD",           "4-byte (1 word)"),
        (b"hello",          "5-byte (partial)"),
        (bytes(range(8)),   "8-byte (2 words)"),
        (b"Hello, ASCON!",  "13-byte"),
    ]

    passed = 0
    for pt, name in tests:
        if test(pt, name):
            passed += 1

    print(f"\n{'='*60}")
    print(f"Results: {passed}/{len(tests)} passed")
    print(f"{'='*60}")
