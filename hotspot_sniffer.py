import argparse
import sys

import scapy.all as scapy
from colorama import Fore, init
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP

init(autoreset=True)


def process_dns_packet(packet):
    # Extract DNS queries (QR == 0 indicates a query)
    if packet.haslayer(DNS) and packet.haslayer(DNSQR) and packet.getlayer(DNS).qr == 0:
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            try:
                dns_query = packet[DNSQR].qname.decode('utf-8')
                print(Fore.GREEN + f"[+] {ip_src:<15} \t {dns_query:<30}")
            except Exception:
                pass


def start_sniffing(interface):
    print(Fore.CYAN + f"[*] Starting DNS Sniffer on interface: {interface}")
    print(Fore.CYAN + "[*] Press CTRL+C to stop.")
    print("-" * 50)
    print(Fore.YELLOW + f"{'Source IP':<15} \t {'DNS Query':<30}")
    print("-" * 50)

    try:
        # Sniff unencrypted DNS traffic on UDP port 53
        scapy.sniff(filter="udp port 53", prn=process_dns_packet, store=0, iface=interface)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Detected CTRL+C. Stopping sniffer...")
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"\n[-] Error: {e}")
        print(Fore.RED + "[!] Ensure you provided the correct interface name and have Administrator privileges.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hotspot DNS Sniffer Tool.")
    parser.add_argument("-i", "--interface", required=True, help="Network interface name of the Hotspot")
    
    args = parser.parse_args()
    start_sniffing(args.interface)
    