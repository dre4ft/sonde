import nmap
import json
import os
import sys

def categorize(ports, osname):
    if 80 in ports or 443 in ports or 3389 in ports:
        return "Service"
    elif 9100 in ports or "printer" in osname.lower():
        return "Maintenance"
    elif "camera" in osname.lower():
        return "Surveillance"
    else:
        return "Endpoint"

def main():
    # Vérification des droits root
    if os.geteuid() != 0:
        print("[❌] Ce script doit être exécuté avec sudo pour la détection d'OS (-O).")
        print("💡 Utilise : sudo ~/venv-sonde/bin/python3 scan.py")
        sys.exit(1)

    scanner = nmap.PortScanner()
    print("[🔍] Scan du réseau en cours...")

    try:
        # 🛠️ Remplace cette plage IP si nécessaire selon ton réseau
        scanner.scan(hosts='192.168.100.0/24', arguments='-O -T4')
    except Exception as e:
        print(f"[❌] Erreur lors du scan : {e}")
        sys.exit(1)

    results = []

    for host in scanner.all_hosts():
        ports = list(scanner[host].get('tcp', {}).keys())

        osmatches = scanner[host].get('osmatch', [])
        if osmatches:
            osname = osmatches[0].get('name', 'Unknown')
        else:
            osname = 'Unknown'

        role = categorize(ports, osname)

        results.append({
            "ip": host,
            "os": osname,
            "ports": ports,
            "role": role
        })

    with open("results.json", "w") as f:
        json.dump(results, f, indent=4)

    print("[✅] Scan terminé. Résultats enregistrés dans results.json.")

if __name__ == "__main__":
    main()
