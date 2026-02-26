from scapy.all import ARP, Ether, srp

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered = srp(packet, timeout=2, verbose=False)[0]
    if answered:
        return answered[0][1].hwsrc
    return None
