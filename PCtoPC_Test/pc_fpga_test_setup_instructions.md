# PC and FPGA Test Setup Instructions

The setup is as follows:

- **PC1 (Linux)** is connected to **ENET0**
  - Top Ethernet port
  - Plaintext side
  - Network: `10.0.0.x`

- **PC2 (Windows)** is connected to **ENET1**
  - Bottom Ethernet port
  - Encrypted side
  - Network: `192.168.1.x`

---

## Steps for the Windows PC — PC2

If Python is not installed on the Windows computer, install it first.

### 1. Install Python

1. Go to `python.org/downloads`.
2. Download the latest Python 3.x version.
3. During installation, make sure to check:

```text
Add python.exe to PATH
```

4. Click **Install Now**.

---

### 2. Configure the IP address

Open the Ethernet adapter settings:

```text
Control Panel → Network Connections → Ethernet Adapter → Properties
```

Then open:

```text
Internet Protocol Version 4 (TCP/IPv4) → Properties
```

Set the following values:

```text
IP address: 192.168.1.129
Subnet mask: 255.255.255.0
Gateway: leave empty
```

---

### 3. Add the ARP entry

Open **Command Prompt as Administrator** and run:

```cmd
arp -s 192.168.1.128 02-00-00-00-00-01
```

---

### 4. Copy the required files

Copy the following files to the same folder on the Windows PC, for example to the Desktop:

```text
pc2_test.py
ascon.py
```

The `ascon.py` file can be taken from the Linux system from this path:

```text
~/Desktop/alex2/verilog-ethernet/example/DE2-115/fpga/rtl/ascon-verilog/ascon.py
```

---

### 5. Temporarily disable the firewall

Temporarily turn off Windows Defender Firewall:

```text
Windows Defender Firewall → Turn Windows Defender Firewall on or off
```

Disable it for both private and public networks during testing.

---

### 6. Run the PC2 test script

Open Command Prompt, go to the folder where the files are located, and run:

```cmd
cd %USERPROFILE%\Desktop
python pc2_test.py 1
```

PC2 should now wait for incoming encrypted packets.

---

## Steps for the Linux PC — PC1

### 1. Configure the IP address

Open a terminal and run:

```bash
sudo ip addr add 10.0.0.2/24 dev enp45s0
sudo ip link set enp45s0 up
sudo arp -s 10.0.0.1 02:00:00:00:00:00 -i enp45s0
```

---

### 2. Run the PC1 test script

Go to the folder where `pc1_test.py` is located and run:

```bash
cd ~/Desktop
python3 pc1_test.py 1
```

---

## Test Order

Follow this order during the test:

1. Program the FPGA.
2. Press **KEY3** to reset the FPGA design.
3. On **PC2 / Windows**, run:

```cmd
python pc2_test.py 1
```

4. On **PC1 / Linux**, run:

```bash
python3 pc1_test.py 1
```

5. PC1 sends the plaintext packet through ENET0.
6. The FPGA encrypts the packet and forwards it to ENET1.
7. PC2 should receive and display the encrypted packet.
