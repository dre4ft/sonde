from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

def analyze_packet(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        proto = pkt[IP].proto

        # Protocole
        if TCP in pkt:
            l4_proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            l4_proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        elif ICMP in pkt:
            l4_proto = "ICMP"
            sport = "-"
            dport = "-"
        else:
            l4_proto = f"PROTO-{proto}"
            sport = "-"
            dport = "-"

        # Payload application
        if Raw in pkt:
            payload = pkt[Raw].load
            try:
                payload_str = payload.decode('utf-8', errors='replace')
            except:
                payload_str = repr(payload)
        else:
            payload_str = ""

        print(f"[{datetime.now().strftime('%H:%M:%S')}] {ip_src}:{sport} -> {ip_dst}:{dport} | {l4_proto}")
        if payload_str:
            print(f"  📄 Payload: {payload_str[:200]}")
            print("-" * 80)

def start_sniffer(interface="en0", packet_count=0):
    print(f"🎯 Sniffing interface '{interface}' (Ctrl+C pour arrêter)...")
    sniff(iface=interface, prn=analyze_packet, store=0, count=packet_count)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Sonde passive type Wireshark")
    parser.add_argument("-i", "--interface", default="en0", help="Interface réseau à écouter (ex: en0, lo0)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Nombre de paquets à capturer (0 = infini)")

    args = parser.parse_args()
    start_sniffer(interface=args.interface, packet_count=args.count)
