# Local ARP & DNS Spoofer 🕵️‍♂️

![Python](https://img.shields.io/badge/python-3.x-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)

A Python-based educational tool designed for local network analysis and lab environments. This project demonstrates how ARP spoofing (cache poisoning) works on a local network and performs basic DNS sniffing to intercept unencrypted DNS queries.

> ⚠️ **DISCLAIMER:** This tool is strictly developed for **educational purposes, network engineering studies, and authorized penetration testing only**. Do not use this script on any network where you do not have explicit permission from the network owner. The author is not responsible for any misuse or damage caused by this program.

##  Features
- **Dynamic ARP Spoofing:** Automatically resolves MAC addresses for both the target and the gateway before initiating the attack.
- **DNS Sniffing:** Intercepts and logs unencrypted DNS queries (UDP Port 53) in real-time.
- **Hotspot Mode:** Includes a standalone script (`hotspot_sniffer.py`) to sniff traffic directly if the target is connected to the attacker's own mobile hotspot.
- **Graceful Auto-Restore:** Restores the original ARP tables upon exit (CTRL+C) to prevent network disruption or denial of service (DoS).
- **Clean Console UI:** Utilizes `colorama` for a structured and readable terminal output.

##  Prerequisites
- **Python 3.x** installed.
- **Root/Administrator privileges** (Required for raw socket access and packet manipulation).
- **Packet Capture Library:** 
- Windows: [Npcap](https://npcap.com/) (Make sure "Install Npcap in WinPcap API-compatible Mode" is checked).
- Linux: `libpcap` (Usually pre-installed, or install via `sudo apt install libpcap-dev`).

##  Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/doflalord/Local-ARP-DNS-Spoofer.git
   cd Local-ARP-DNS-Spoofer
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

##  Usage

### 1. ARP Spoofing & Sniffing Mode (`arp_spoofer.py`)
Use this mode when both the attacker and the target are on the same local network (e.g., connected to the same Wi-Fi router).

**Syntax:**
```bash
python arp_spoofer.py -t <TARGET_IP> -s <GATEWAY_IP> -i <INTERFACE_NAME>
```

**Example (Windows):**
```bash
python arp_spoofer.py -t 192.168.1.15 -s 192.168.1.1 -i "Wi-Fi"
```

**Example (Linux):**
```bash
sudo python arp_spoofer.py -t 192.168.1.15 -s 192.168.1.1 -i eth0
```

### 2. Hotspot Sniffing Mode (`hotspot_sniffer.py`)
Use this mode if the target device is connected directly to a Mobile Hotspot hosted by the attacker's machine. (No ARP spoofing is needed here since traffic naturally flows through the attacker's gateway).

**Syntax:**
```bash
python hotspot_sniffer.py -i <INTERFACE_NAME>
```

**Example:**
```bash
python hotspot_sniffer.py -i "Local Area Connection* 2"
```
*(Note: Use `Get-NetAdapter` in PowerShell or `ifconfig` in Linux to find the exact interface name).*

##  How it Works (Under the Hood)

This tool is built to understand the vulnerabilities in Layer 2 (Data Link) and Layer 7 (Application) protocols:

1. **ARP Cache Poisoning (Layer 2):** The ARP protocol lacks authentication. `arp_spoofer.py` exploits this by sending unsolicited ARP replies (Opcode 2) to the target, mapping the Gateway's IP to the Attacker's MAC address, and vice versa. This creates a Man-in-the-Middle (MitM) position.
2. **Packet Forwarding:** For the target to maintain internet access, the attacker machine must have **IP Forwarding** enabled.
3. **DNS Sniffing (Layer 7):** While forwarding the packets, `scapy.sniff()` listens on UDP port 53. If a packet contains a `DNSQR` (DNS Query Record) layer, it extracts and decodes the requested domain name, demonstrating the risks of unencrypted DNS traffic.

##  License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
