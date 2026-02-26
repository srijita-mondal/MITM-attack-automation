from scapy.all import sniff, DNS, DNSQR

def dns_monitor(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode()
        print(f"DNS Query: {query}")

sniff(filter="udp port 53", prn=dns_monitor, store=False)
