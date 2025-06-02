from scapy.all import *
import random
import time

def simulate_traffic(interface="lo0", count=100, delay=0.1):
    print(f"🚀 Envoi de {count} paquets sur l'interface {interface}...")

    for i in range(count):
        pkt_type = random.choice(['icmp', 'tcp', 'udp'])

        if pkt_type == 'icmp':
            pkt = IP(dst="127.0.0.1") / ICMP() / f"ICMP test {i}"
        elif pkt_type == 'tcp':
            pkt = IP(dst="127.0.0.1") / TCP(dport=random.randint(1024, 65535), flags="S") / f"TCP test {i}"
        else:
            pkt = IP(dst="127.0.0.1") / UDP(dport=random.randint(1024, 65535)) / f"UDP test {i}"

        send(pkt, verbose=False)
        time.sleep(delay)

    print("✅ Simulation terminée.")

if __name__ == "__main__":
    simulate_traffic(interface="lo0", count=200, delay=0.05)
