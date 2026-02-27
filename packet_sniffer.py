from scapy.all import sniff, IP, TCP, Raw

def process_packet(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        print(f"[IP] {src} -> {dst}")

        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                text = payload.decode(errors="ignore")
                if text.strip():
                    print(f"[DATA] {text[:80]}")
            except:
                pass

def main():
    print("[+] Packet sniffing started...")
    sniff(store=False, prn=process_packet)

if __name__ == "__main__":
    main()
