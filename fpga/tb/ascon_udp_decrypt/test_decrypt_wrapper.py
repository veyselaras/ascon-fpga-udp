"""
Cocotb test for ascon_udp_decrypt

Tests:
  1. Use pyascon to encrypt a plaintext → get (nonce, AD, CT, tag)
  2. Feed (nonce + AD + CT + tag) to decrypt wrapper via AXI-Stream input
  3. Read decrypted plaintext from AXI-Stream output
  4. Verify against original plaintext
  5. Also test auth failure case (corrupted tag → no output)

Install deps:
  pip install cocotb
"""

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, Timer

# ---- pyascon import ----
import sys
sys.path.insert(0, "./ascon-verilog")
try:
    from ascon import ascon_encrypt
    HAS_ASCON = True
except ImportError:
    HAS_ASCON = False

# ---- Constants (must match RTL) ----
FIXED_KEY   = bytes([0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
                     0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00])
FIXED_NONCE = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])
FIXED_AD    = bytes([0x00, 0xFF, 0xEE, 0xDD])


async def reset_dut(dut):
    """Apply reset for a few clock cycles."""
    dut.rst_n.value = 0
    dut.s_axis_tdata.value = 0
    dut.s_axis_tvalid.value = 0
    dut.s_axis_tlast.value = 0
    dut.m_axis_tready.value = 0

    for _ in range(10):
        await RisingEdge(dut.clk)

    dut.rst_n.value = 1
    for _ in range(5):
        await RisingEdge(dut.clk)


async def send_ciphertext_packet(dut, packet: bytes):
    """Send encrypted packet (nonce+AD+CT+tag) via AXI-Stream input."""
    dut._log.info(f"Sending {len(packet)} bytes (encrypted packet)")

    for i, byte in enumerate(packet):
        dut.s_axis_tdata.value = byte
        dut.s_axis_tvalid.value = 1
        dut.s_axis_tlast.value = 1 if (i == len(packet) - 1) else 0

        # Wait for tready
        while True:
            await RisingEdge(dut.clk)
            if dut.s_axis_tready.value == 1:
                break

    # Deassert after last byte
    await RisingEdge(dut.clk)
    dut.s_axis_tvalid.value = 0
    dut.s_axis_tlast.value = 0


async def receive_plaintext(dut, timeout_cycles=5000):
    """Receive decrypted plaintext bytes via AXI-Stream output."""
    dut.m_axis_tready.value = 1
    received = []
    cycle_cnt = 0

    while cycle_cnt < timeout_cycles:
        await RisingEdge(dut.clk)
        cycle_cnt += 1

        if dut.m_axis_tvalid.value == 1 and dut.m_axis_tready.value == 1:
            received.append(int(dut.m_axis_tdata.value))

            if dut.m_axis_tlast.value == 1:
                break

    dut.m_axis_tready.value = 0
    result = bytes(received)
    dut._log.info(f"Received {len(result)} bytes: {result.hex()}")
    return result


def build_encrypted_packet(plaintext: bytes):
    """Use pyascon to encrypt and build packet: nonce + AD + CT + tag."""
    result = ascon_encrypt(FIXED_KEY, FIXED_NONCE, FIXED_AD, plaintext,
                           variant="Ascon-AEAD128")
    if isinstance(result, tuple):
        ct  = bytes(result[0])
        tag = bytes(result[1])
    else:
        ct  = result[:len(plaintext)]
        tag = result[len(plaintext):]

    # Packet: nonce(16) + AD(4) + CT(N) + tag(16)
    packet = FIXED_NONCE + FIXED_AD + ct + tag
    return packet, ct, tag


async def run_decrypt_test(dut, plaintext: bytes, test_name: str,
                            corrupt_tag: bool = False,
                            expect_output: bool = True):
    """Run a single decryption test.

    Args:
        plaintext: the original plaintext to encrypt then decrypt
        corrupt_tag: if True, flip a bit in the tag (auth should fail)
        expect_output: if True, expect plaintext output; if False, expect timeout
    """
    dut._log.info(f"=== {test_name}: plaintext={plaintext.hex()} ({len(plaintext)} bytes) ===")

    if not HAS_ASCON:
        dut._log.error("pyascon not available, cannot build test packet")
        assert False, "pyascon required"

    # Build encrypted packet using pyascon
    packet, ct, tag = build_encrypted_packet(plaintext)

    dut._log.info(f"  Encrypted packet: {packet.hex()}")
    dut._log.info(f"    Nonce: {packet[0:16].hex()}")
    dut._log.info(f"    AD:    {packet[16:20].hex()}")
    dut._log.info(f"    CT:    {ct.hex()}")
    dut._log.info(f"    Tag:   {tag.hex()}")

    # Optionally corrupt the tag (flip a bit)
    if corrupt_tag:
        packet = bytearray(packet)
        packet[-1] ^= 0x01   # flip LSB of last byte
        packet = bytes(packet)
        dut._log.info(f"  Tag corrupted (flipped LSB of last byte)")

    # Send encrypted packet to wrapper
    await send_ciphertext_packet(dut, packet)

    if expect_output:
        # Receive decrypted plaintext
        decrypted = await receive_plaintext(dut)

        if len(decrypted) != len(plaintext):
            dut._log.error(f"  FAIL: Length mismatch. Expected {len(plaintext)}, got {len(decrypted)}")
            assert False, f"{test_name} length mismatch"

        if decrypted == plaintext:
            dut._log.info(f"  >>> PASS: Decrypted = {decrypted.hex()} (matches plaintext) <<<")
        else:
            dut._log.error(f"  >>> FAIL <<<")
            dut._log.error(f"    Expected: {plaintext.hex()}")
            dut._log.error(f"    Got:      {decrypted.hex()}")
            for i in range(min(len(decrypted), len(plaintext))):
                if decrypted[i] != plaintext[i]:
                    dut._log.error(f"    Byte {i}: expected 0x{plaintext[i]:02x}, got 0x{decrypted[i]:02x}")
            assert False, f"{test_name} plaintext mismatch"
    else:
        # Expect NO output (auth should fail)
        dut.m_axis_tready.value = 1
        got_output = False
        for _ in range(3000):
            await RisingEdge(dut.clk)
            if dut.m_axis_tvalid.value == 1 and dut.m_axis_tready.value == 1:
                got_output = True
                break
        dut.m_axis_tready.value = 0

        if got_output:
            dut._log.error(f"  >>> FAIL: Got output despite corrupted tag <<<")
            assert False, f"{test_name} should have failed auth"
        else:
            dut._log.info(f"  >>> PASS: No output (auth correctly rejected) <<<")

    # Wait a bit before next test
    for _ in range(50):
        await RisingEdge(dut.clk)


# =====================================================
# Test Cases
# =====================================================

@cocotb.test()
async def test_4byte_decrypt(dut):
    """Test decryption of 4-byte plaintext."""
    clock = Clock(dut.clk, 8, unit="ns")  # 125 MHz
    cocotb.start_soon(clock.start())
    await reset_dut(dut)
    await run_decrypt_test(dut, b"\x41\x42\x43\x44", "4-byte")
    for _ in range(100):
        await RisingEdge(dut.clk)


@cocotb.test()
async def test_1byte_decrypt(dut):
    """Test decryption of 1-byte plaintext."""
    clock = Clock(dut.clk, 8, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)
    await run_decrypt_test(dut, b"\x41", "1-byte")
    for _ in range(100):
        await RisingEdge(dut.clk)


@cocotb.test()
async def test_5byte_hello_decrypt(dut):
    """Test decryption of 'hello' (5 bytes)."""
    clock = Clock(dut.clk, 8, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)
    await run_decrypt_test(dut, b"hello", "5-byte-hello")
    for _ in range(100):
        await RisingEdge(dut.clk)


@cocotb.test()
async def test_8byte_decrypt(dut):
    """Test decryption of 8-byte plaintext (exact 2 words)."""
    clock = Clock(dut.clk, 8, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)
    await run_decrypt_test(dut, bytes(range(8)), "8-byte")
    for _ in range(100):
        await RisingEdge(dut.clk)


@cocotb.test()
async def test_13byte_decrypt(dut):
    """Test decryption of 'Hello, ASCON!' (13 bytes)."""
    clock = Clock(dut.clk, 8, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)
    await run_decrypt_test(dut, b"Hello, ASCON!", "13-byte")
    for _ in range(100):
        await RisingEdge(dut.clk)


@cocotb.test()
async def test_consecutive_decrypt(dut):
    """Test two consecutive decryption packets (wrapper must return to IDLE)."""
    clock = Clock(dut.clk, 8, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    await run_decrypt_test(dut, b"first",  "consecutive-1")
    await run_decrypt_test(dut, b"second", "consecutive-2")
    for _ in range(100):
        await RisingEdge(dut.clk)


@cocotb.test()
async def test_corrupted_tag(dut):
    """Test that corrupted tag is rejected (auth should fail)."""
    clock = Clock(dut.clk, 8, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    # Corrupt the tag — auth should fail, no output expected
    await run_decrypt_test(dut, b"hello", "corrupted-tag",
                           corrupt_tag=True, expect_output=False)
    for _ in range(100):
        await RisingEdge(dut.clk)


@cocotb.test()
async def test_recovery_after_auth_fail(dut):
    """Test that wrapper recovers after auth failure and accepts new packet."""
    clock = Clock(dut.clk, 8, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    # First, corrupted tag → should be rejected
    await run_decrypt_test(dut, b"bad",  "corrupted-first",
                           corrupt_tag=True, expect_output=False)

    # Then, valid packet → should decrypt normally
    await run_decrypt_test(dut, b"good", "valid-after-corrupt")
    for _ in range(100):
        await RisingEdge(dut.clk)
