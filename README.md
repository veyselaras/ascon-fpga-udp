# ASCON-AEAD128 FPGA Encryption Gateway


A real-time hardware encryption gateway built on the **Terasic DE2-115 FPGA** (Cyclone IV E). The FPGA sits between a device and the network, encrypting all outgoing traffic and decrypting all incoming traffic — transparently and entirely in hardware.

Uses the **ASCON-AEAD128** algorithm, standardized by NIST as [SP 800-232](https://csrc.nist.gov/pubs/sp/800/232/final) for lightweight authenticated encryption.

## Architecture

```
                              FPGA (Encryption Gateway)
                    ┌──────────────────────────────────────────┐
                    │                                          │
  PLC/PC ──plain──► │ ENET0 RX → FIFO → Encrypt → FIFO → ENET1 TX │ ──cipher──► Network
 (10.0.0.2)        │                                          │          (192.168.1.129)
                    │                                          │
  PLC/PC ◄──plain── │ ENET0 TX ← FIFO ← Decrypt ← FIFO ← ENET1 RX │ ◄──cipher── Network
                    │                                          │
                    └──────────────────────────────────────────┘
                         10.0.0.1              192.168.1.128
                        (plaintext)            (encrypted)
```

- **ENET0** connects directly to the device (PLC, PC, sensor, etc.) with a cable — no switch. Plaintext never leaves this link.
- **ENET1** connects to the network. Only encrypted and authenticated data appears here.
- Both directions work simultaneously. The device needs no special software — it sends and receives normal UDP packets.

## How It Works

### Encrypt Path (Device → Network)

1. Device sends a UDP packet to FPGA ENET0 (port 1234)
2. Packet crosses from 125 MHz to 62.5 MHz domain via async FIFO
3. ASCON-AEAD128 encrypts the payload and generates an authentication tag
4. Output packet (nonce + AD + ciphertext + tag) crosses back to 125 MHz
5. FPGA sends the encrypted UDP packet out through ENET1

### Decrypt Path (Network → Device)

1. Encrypted UDP packet arrives at FPGA ENET1 (port 1234)
2. Packet crosses to 62.5 MHz domain via async FIFO
3. ASCON-AEAD128 decrypts the ciphertext and verifies the authentication tag
4. If tag is valid: plaintext is sent to the device through ENET0
5. If tag is invalid: packet is silently dropped — nothing reaches the device

### Encrypted Packet Format

```
[Nonce - 16 bytes][AD - 4 bytes][Ciphertext - N bytes][Tag - 16 bytes]
```

Total overhead: 36 bytes per packet.

## Modules

| Module | Count | Purpose |
|--------|-------|---------|
| `udp_complete` | 2 | Full UDP/IP/ARP stack for each Ethernet port |
| `eth_mac_1g_rgmii_fifo` | 2 | Gigabit Ethernet MAC (RGMII) for each port |
| `ascon_udp_wrapper` | 1 | Encrypt wrapper — feeds plaintext to ASCON, outputs nonce+AD+CT+tag |
| `ascon_udp_decrypt` | 1 | Decrypt wrapper — parses nonce+AD+CT+tag, outputs plaintext |
| `axis_async_fifo` | 4 | Clock domain crossing (125 MHz ↔ 62.5 MHz) |
| `true_dual_port_ram` | 4 | Block RAM (M9K) for packet buffering |

## Clock Domains

| Clock | Frequency | Usage |
|-------|-----------|-------|
| CLK0 | 125 MHz | Ethernet MAC, UDP/IP, ARP |
| CLK1 | 125 MHz + 90° | RGMII TX timing |
| CLK2 | 62.5 MHz | ASCON encrypt/decrypt cores |

All three clocks are generated from the 50 MHz board oscillator using the Cyclone IV PLL. Clock domain crossing between 125 MHz and 62.5 MHz is handled by asynchronous FIFOs with proper synchronization.

## Security Features

- **Physical isolation**: Plaintext exists only on the direct cable between the device and ENET0. No plaintext ever reaches the network switch.
- **Authenticated encryption**: ASCON-AEAD128 provides both confidentiality and integrity. Tampered packets fail tag verification and are dropped.
- **Dynamic nonce**: An LFSR generates a unique 128-bit nonce for each packet, preventing nonce reuse attacks.
- **Pure hardware**: No CPU, no software, no OS — no software-level attack surface.

## Network Configuration

| Parameter | ENET0 (Plaintext) | ENET1 (Encrypted) |
|-----------|-------------------|-------------------|
| IP Address | 10.0.0.1 | 192.168.1.128 |
| MAC Address | 02:00:00:00:00:00 | 02:00:00:00:00:01 |
| Subnet | 255.255.255.0 | 255.255.255.0 |
| Target IP | 10.0.0.2 (device) | 192.168.1.129 (remote FPGA) |
| UDP Port | 1234 | 1234 |

Two separate subnets ensure plaintext and encrypted traffic are physically separated.

## Resource Usage

| Resource | Used | Available | Utilization |
|----------|------|-----------|-------------|
| Logic Elements | 15,562 | 114,480 | ~14% |
| Registers | 8,010 | - | - |
| PLLs | 1 | 4 | 25% |

## Hardware

- **FPGA Board**: [Terasic DE2-115](https://www.terasic.com.tw/cgi-bin/page/archive.pl?No=502)
- **FPGA Chip**: Cyclone IV E (EP4CE115F29C7)
- **Ethernet PHY**: Marvell Alaska 88E1111 × 2 (RGMII, 1000BASE-T)
- **Connection**: Cat5e/Cat6 cables, one per port

## Verification

### RTL Simulation (Cocotb + Verilator)

- Encrypt wrapper: 7 tests (1, 4, 5, 7, 8, 13 bytes + consecutive packets)
- Decrypt wrapper: 8 tests (same sizes + corrupted tag + recovery after auth fail)
- All tests verified against Python reference implementation (pyascon)

### Hardware Testing

Tested with two PCs:
- **PC1 (Linux)**: Connected to ENET0, sends plaintext, receives decrypted data
- **PC2 (Windows)**: Connected to ENET1, receives encrypted packets, sends encrypted data for decrypt testing

All 5 test vectors verified — ciphertext and tag matched pyascon reference output byte-for-byte.

## Project Structure

```
fpga/
├── rtl/
│   ├── fpga.v                    # Top level (PLL, resets, GPIO)
│   ├── fpga_core.v               # Main logic (dual-port, bidirectional)
│   ├── ascon_udp_wrapper.sv      # Encrypt wrapper
│   ├── ascon_udp_decrypt.sv      # Decrypt wrapper
│   ├── true_dual_port_ram.v      # Block RAM module
│   ├── config_local.sv           # Quartus enum width fix
│   └── ascon-verilog/            # ASCON core (submodule)
├── tb/
│   ├── ascon_udp_wrapper/        # Encrypt cocotb testbench
│   └── ascon_udp_decrypt/        # Decrypt cocotb testbench
├── fpga.sdc                      # Timing constraints
└── fpga.qsf                      # Quartus pin assignments
```

## Dependencies

| Library | Provides | Source |
|---------|----------|--------|
| [verilog-ethernet](https://github.com/alexforencich/verilog-ethernet) | Ethernet MAC, UDP/IP, AXI-Stream FIFO, ARP | Alex Forencich |
| [ascon-verilog](https://github.com/rprimas/ascon-verilog) | ASCON-AEAD128 core (SP 800-232) | Robert Primas |

## Quick Start

### Build

1. Clone this repo and initialize submodules
2. Open `fpga/fpga.qpf` in Quartus Prime
3. Compile (Analysis & Synthesis → Fitter → Assembler)
4. Program the FPGA via JTAG

## Quick Start

### Hardware Connections

Connect the two PCs to the FPGA Ethernet ports as follows:

| Device        | FPGA Port          | Role           | IP Network    |
| ------------- | ------------------ | -------------- | ------------- |
| PC1 — Linux   | ENET0, top port    | Plaintext side | `10.0.0.x`    |
| PC2 — Windows | ENET1, bottom port | Encrypted side | `192.168.1.x` |

---

## Build

1. Clone the repository and initialize the submodules:

```bash
git clone --recursive <repository-url>
cd <repository-folder>
```

If the repository was cloned without `--recursive`, run:

```bash
git submodule update --init --recursive
```

2. Open the Quartus project:

```text
fpga/fpga.qpf
```

3. Compile the design in Quartus Prime:

```text
Analysis & Synthesis → Fitter → Assembler
```

4. Program the FPGA through JTAG.

5. After programming, press **KEY3** to reset the FPGA design.

---

## Test Setup — Encrypt Path

This test verifies the encryption path:

```text
PC1/Linux → ENET0 → FPGA encryption gateway → ENET1 → PC2/Windows
```

PC1 sends plaintext UDP data to the FPGA.
The FPGA encrypts the payload and forwards the encrypted packet to PC2.

---

### PC1 — Linux Setup

Connect PC1 to **ENET0**.

Configure the Linux Ethernet interface:

```bash
sudo ip addr add 10.0.0.2/24 dev enp45s0
sudo ip link set enp45s0 up
sudo arp -s 10.0.0.1 02:00:00:00:00:00 -i enp45s0
```

> Note: If your Linux Ethernet interface name is different, replace `enp45s0` with the correct interface name. You can check it using:

```bash
ip link
```

---

### PC2 — Windows Setup

Connect PC2 to **ENET1**.

Set the Windows Ethernet adapter manually:

```text
IP address: 192.168.1.129
Subnet mask: 255.255.255.0
Gateway: leave empty
```

Open **Command Prompt as Administrator** and add the ARP entry:

```cmd
arp -s 192.168.1.128 02-00-00-00-00-01
```

Make sure Python 3 is installed on Windows. During installation, enable:

```text
Add python.exe to PATH
```

Temporarily disable Windows Defender Firewall during the test if packets are blocked.

---

## Running the Test

Start the receiver on **PC2 / Windows** first:

```cmd
python pc2_test.py 1
```

Then start the sender on **PC1 / Linux**:

```bash
python3 pc1_test.py 1
```

Expected result:

```text
PC1 sends a plaintext UDP packet.
The FPGA receives it from ENET0.
The FPGA encrypts the UDP payload.
The encrypted packet is transmitted from ENET1.
PC2 receives and displays the encrypted packet.
```

The received encrypted packet should contain the nonce, associated data, ciphertext, and authentication tag.


## Author

**Veysel Aras**

Advisor: Prof. Dr. İbrahim Özçelik

## Acknowledgments

- [Robert Primas](https://github.com/rprimas) — ASCON Verilog implementation
- [Alex Forencich](https://github.com/alexforencich) — Verilog Ethernet components

## License

This project uses open-source components. See individual repositories for their licenses.
