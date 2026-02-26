from scapy.all import sniff, IP, TCP, UDP

def process(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "IP"
        print(f"{src} -> {dst} | {proto}")

sniff(filter="ip", prn=process, store=False)
