"""
Cocotb test for ascon_udp_wrapper

Tests:
  1. Send plaintext via AXI-Stream input
  2. Wait for ASCON encryption
  3. Read nonce + AD + ciphertext + tag from AXI-Stream output
  4. Verify against pyascon reference

Install deps:
  pip install cocotb pyascon
"""

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, Timer, FallingEdge

# ---- pyascon import ----
import sys
sys.path.insert(0, "../../rtl/ascon-verilog")
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
FIXED_AD    = bytes([0x00, 0xFF, 0xEE, 0xDD, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

# Sadece ilk 4 byte AD kullaniliyor (tek word)
FIXED_AD_SHORT = FIXED_AD[:4]


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


async def send_plaintext(dut, data: bytes):
    """Send plaintext bytes via AXI-Stream input."""
    dut._log.info(f"Sending {len(data)} bytes: {data.hex()}")

    for i, byte in enumerate(data):
        dut.s_axis_tdata.value = byte
        dut.s_axis_tvalid.value = 1
        dut.s_axis_tlast.value = 1 if (i == len(data) - 1) else 0

        # Wait for tready
        while True:
            await RisingEdge(dut.clk)
            if dut.s_axis_tready.value == 1:
                break

    # Deassert after last byte
    await RisingEdge(dut.clk)
    dut.s_axis_tvalid.value = 0
    dut.s_axis_tlast.value = 0


async def receive_output(dut, timeout_cycles=5000):
    """Receive output bytes via AXI-Stream output."""
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


def parse_output(data: bytes, pt_len: int):
    """Parse output packet: nonce(16) + AD(4) + ciphertext(N) + tag(16)."""
    nonce = data[0:16]
    ad    = data[16:20]
    ct    = data[20:20 + pt_len]
    tag   = data[20 + pt_len:20 + pt_len + 16]
    return nonce, ad, ct, tag


def verify_with_pyascon(plaintext, ct_got, tag_got):
    if not HAS_ASCON:
        return None
    result = ascon_encrypt(FIXED_KEY, FIXED_NONCE, FIXED_AD_SHORT, plaintext, variant="Ascon-AEAD128")
    if isinstance(result, tuple):
        expected_ct  = bytes(result[0])
        expected_tag = bytes(result[1])
    else:
        expected_ct  = result[:len(plaintext)]
        expected_tag = result[len(plaintext):]
    return expected_ct, expected_tag


async def run_single_test(dut, plaintext: bytes, test_name: str):
    """Run a single encryption test."""
    dut._log.info(f"=== {test_name}: {len(plaintext)} bytes ===")

    # Send plaintext
    await send_plaintext(dut, plaintext)

    # Receive output
    output = await receive_output(dut)

    expected_len = 16 + 4 + len(plaintext) + 16  # nonce + AD + CT + tag
    assert len(output) == expected_len, \
        f"Length mismatch: expected {expected_len}, got {len(output)}"

    # Parse
    nonce, ad, ct, tag = parse_output(output, len(plaintext))
    dut._log.info(f"  Nonce: {nonce.hex()}")
    dut._log.info(f"  AD:    {ad.hex()}")
    dut._log.info(f"  CT:    {ct.hex()}")
    dut._log.info(f"  Tag:   {tag.hex()}")

    # Verify nonce
    expected_nonce = bytes([FIXED_NONCE[i] for i in range(16)])
    assert nonce == expected_nonce, \
        f"Nonce mismatch!\n  Expected: {expected_nonce.hex()}\n  Got:      {nonce.hex()}"

    # Verify AD
    assert ad == FIXED_AD_SHORT, \
        f"AD mismatch!\n  Expected: {FIXED_AD_SHORT.hex()}\n  Got:      {ad.hex()}"

    # Verify ciphertext != plaintext (encrypted)
    if len(plaintext) > 0:
        assert ct != plaintext, "Ciphertext equals plaintext — encryption may not be working!"

    # Verify against pyascon
    if HAS_ASCON:
        expected_ct, expected_tag = verify_with_pyascon(plaintext, ct, tag)
        dut._log.info(f"  Expected CT:  {expected_ct.hex()}")
        dut._log.info(f"  Expected Tag: {expected_tag.hex()}")

        if ct == expected_ct and tag == expected_tag:
            dut._log.info(f"  >>> PASS: {test_name} <<<")
        else:
            dut._log.error(f"  >>> FAIL: {test_name} <<<")
            if ct != expected_ct:
                for i in range(len(ct)):
                    if ct[i] != expected_ct[i]:
                        dut._log.error(f"    CT byte {i}: expected 0x{expected_ct[i]:02x}, got 0x{ct[i]:02x}")
            if tag != expected_tag:
                dut._log.error(f"    Tag mismatch")
            assert False, f"{test_name} failed"
    else:
        dut._log.info(f"  (pyascon not available, skipping verification)")

    # Wait a bit before next test
    for _ in range(20):
        await RisingEdge(dut.clk)


# =====================================================
# Test Cases
# =====================================================

@cocotb.test()
async def test_4byte(dut):
    """Test 4-byte plaintext (exact 1 word)."""
    clock = Clock(dut.clk, 8, units="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)
    await run_single_test(dut, b"\x41\x42\x43\x44", "4-byte")
    

@cocotb.test()
async def test_1byte(dut):
    """Test 1-byte plaintext."""
    clock = Clock(dut.clk, 8, units="ns")  # 125 MHz
    cocotb.start_soon(clock.start())
    await reset_dut(dut)
    await run_single_test(dut, b"\x41", "1-byte")


@cocotb.test()
async def test_5byte_hello(dut):
    """Test 'hello' (5 bytes, partial second word)."""
    clock = Clock(dut.clk, 8, units="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)
    await run_single_test(dut, b"hello", "5-byte-hello")


@cocotb.test()
async def test_8byte(dut):
    """Test 8-byte plaintext (exact 2 words)."""
    clock = Clock(dut.clk, 8, units="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)
    await run_single_test(dut, bytes(range(8)), "8-byte")


@cocotb.test()
async def test_13byte(dut):
    """Test 'Hello, ASCON!' (13 bytes)."""
    clock = Clock(dut.clk, 8, units="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)
    await run_single_test(dut, b"Hello, ASCON!", "13-byte")


@cocotb.test()
async def test_consecutive_packets(dut):
    """Test two consecutive packets (wrapper must return to IDLE)."""
    clock = Clock(dut.clk, 8, units="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    await run_single_test(dut, b"first", "consecutive-1")
    await run_single_test(dut, b"second", "consecutive-2")
