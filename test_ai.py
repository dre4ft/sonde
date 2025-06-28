#!/usr/bin/env python3
"""
test_ai_classification.py - Test du système de classification IA hybride
"""
from ai_local import hybrid_classifier, classify_scan_results
import json

def test_string_classification():
    """Test de la classification depuis des strings"""
    print("=== TEST CLASSIFICATION DEPUIS STRINGS ===\n")
    
    test_cases = [
        "IP=192.168.1.1, hostname=livebox.home, OS=Linux, ports=[53,80,443], services=[dns,http,https]",
        "IP=192.168.1.19, hostname=xiaomi-13t-pro.home, OS=Android, ports=[], services=[]",
        "IP=192.168.1.100, hostname=srv-db01, OS=Ubuntu Linux, ports=[3306,22], services=[mysql,ssh]",
        "IP=192.168.1.50, hostname=HP-LaserJet-P2055, OS=Printer, ports=[9100,80], services=[jetdirect,http]",
        "IP=192.168.1.75, hostname=cam-entrance, OS=Linux embedded, ports=[554,80], services=[rtsp,http]",
        "IP=192.168.1.200, hostname=DESKTOP-ABC123, OS=Windows 10, ports=[445,3389], services=[smb,rdp]",
        "IP=192.168.1.150, hostname=alexa-echo-dot, OS=Unknown, ports=[67,68], services=[dhcp]",
        "IP=192.168.1.42, hostname=synology-nas, OS=DSM, ports=[5000,5001,445,22], services=[http,https,smb,ssh]",
    ]
    
    for test in test_cases:
        result = hybrid_classifier.classify(test)
        if result:
            print(f"Host: {result['info']['ip']} ({result['info']['hostname']})")
            print(f"  Type détecté : {result['label']}")
            print(f"  Rôle large   : {result['role']}")
            print(f"  Confiance    : {result['score']:.2%}")
            print(f"  Détails      : {result['details']}")
            print()

def test_dict_classification():
    """Test de la classification depuis des dictionnaires (format scan)"""
    print("\n=== TEST CLASSIFICATION DEPUIS DICTIONNAIRES ===\n")
    
    scan_results = [
        {
            "ip": "192.168.1.10",
            "hostname": "macbook-pro.local",
            "os": "Mac OS X 10.15",
            "ports": [22, 5900, 88],
            "services": [
                {"port": 22, "name": "ssh", "product": "OpenSSH", "version": "8.1"},
                {"port": 5900, "name": "vnc", "product": "Apple Remote Desktop", "version": "3.9"},
                {"port": 88, "name": "kerberos", "product": "", "version": ""}
            ]
        },
        {
            "ip": "192.168.1.20",
            "hostname": "nginx-web-01",
            "os": "Ubuntu 20.04",
            "ports": [80, 443, 22],
            "services": [
                {"port": 80, "name": "http", "product": "nginx", "version": "1.18.0"},
                {"port": 443, "name": "https", "product": "nginx", "version": "1.18.0"},
                {"port": 22, "name": "ssh", "product": "OpenSSH", "version": "8.2p1"}
            ]
        },
        {
            "ip": "192.168.1.30",
            "hostname": "hikvision-cam-01",
            "os": "Linux 2.6.x",
            "ports": [554, 80, 8000],
            "services": [
                {"port": 554, "name": "rtsp", "product": "Hikvision IPCam", "version": "V5.5.0"},
                {"port": 80, "name": "http", "product": "Hikvision IPCam", "version": "V5.5.0"},
                {"port": 8000, "name": "http-alt", "product": "", "version": ""}
            ]
        }
    ]
    
    # Classification
    classified_results = classify_scan_results(scan_results.copy())
    
    for result in classified_results:
        print(f"Host: {result['ip']} ({result.get('hostname', 'N/A')})")
        print(f"  OS           : {result['os']}")
        print(f"  Type IA      : {result.get('device_type', 'Non classifié')}")
        print(f"  Rôle         : {result.get('role', 'N/A')}")
        print(f"  Confiance    : {result.get('ai_score', 0):.2%}")
        print(f"  Méthode      : {result.get('ai_method', 'N/A')}")
        print()

def test_edge_cases():
    """Test des cas limites"""
    print("\n=== TEST CAS LIMITES ===\n")
    
    edge_cases = [
        # Aucune info
        "IP=192.168.1.99, hostname=, OS=Unknown, ports=[], services=[]",
        # Beaucoup de ports
        "IP=192.168.1.88, hostname=server, OS=Linux, ports=[22,25,53,80,110,143,443,465,587,993,995,3306,5432], services=[]",
        # Nom ambigu
        "IP=192.168.1.77, hostname=device, OS=Unknown, ports=[161], services=[snmp]",
    ]
    
    for test in edge_cases:
        result = hybrid_classifier.classify(test)
        if result:
            print(f"Test: {test}")
            print(f"  → Classification: {result['label']} (confiance: {result['score']:.2%})")
            print()

def compare_methods():
    """Compare les résultats des différentes méthodes"""
    print("\n=== COMPARAISON DES MÉTHODES ===\n")
    
    test_host = "IP=192.168.1.123, hostname=mysql-server, OS=CentOS 7, ports=[3306,22], services=[mysql,ssh]"
    
    result = hybrid_classifier.classify(test_host)
    if result and 'details' in result:
        print(f"Host test: {test_host}")
        print("\nRésultats par méthode:")
        for method, (role, score) in result['details'].items():
            print(f"  {method:<10} : {role:<15} (score: {score:.2f})")
        print(f"\nRésultat final : {result['label']} (score pondéré: {result['score']:.2f})")

if __name__ == "__main__":
    print("🤖 TEST DU SYSTÈME DE CLASSIFICATION IA HYBRIDE\n")
    
    test_string_classification()
    test_dict_classification()
    test_edge_cases()
    compare_methods()
    
    print("\n✅ Tests terminés!")