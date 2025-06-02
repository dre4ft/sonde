import nmap
import json
import os
import sys
from vulners import Vulners
import os
from BD.db import save_scan_entry


api_key = os.environ.get("VULNERS_API_KEY")

def get_nmap_args(scan_type):
    if scan_type == "quick":
        return "--script nbstat"
    elif scan_type == "standard":
        return "-O -T4"
    elif scan_type == "deep":
        return "-A -T4"
    else:
        return "-O -T4"

def categorize(ports, osname):
    osname = osname.lower()
    if 554 in ports or "camera" in osname:
        return "Surveillance"
    elif 9100 in ports or "printer" in osname:
        return "Maintenance"
    elif 3389 in ports or 80 in ports or 443 in ports:
        return "Service"
    elif "windows" in osname or "mac" in osname:
        return "Endpoint"
    elif "linux" in osname and (22 in ports or 80 in ports):
        return "Endpoint"
    elif len(ports) > 3:
        return "Service"
    else:
        return "Endpoint"
    

def search_cve(product, version):
    if not product or not version:
        return []

    vulners_api = Vulners(api_key)
    query = f"{product} {version}"
    print(f"🔎 Recherche de vulnérabilités pour {query} ...")
    try:
        results = vulners_api.search(query)
        cves = []
        for r in results:
            if "cvelist" in r:
                cves += r["cvelist"]
        sorted_cves = sort_cves_by_year(cves)  
        return list(set(sorted_cves))
    except Exception as e:
        print("⚠️ Erreur recherche CVE:", e)
        return []

def sort_cves_by_year(cves):
    def extract_year(cve_code):
        try:
            # Exemple: "CVE-2023-1111" -> 2023
            return int(cve_code.split('-')[1])
        except (IndexError, ValueError):
            return 0  # Si format inattendu, on met 0 pour trier en début

    return sorted(cves, key=extract_year)

def main():
    results = []
    if os.geteuid() != 0:
        print("[❌] Ce script doit être exécuté avec sudo.")
        sys.exit(1)

    scan_type = sys.argv[1] if len(sys.argv) > 1 else "standard"
    target = sys.argv[2] if len(sys.argv) > 2 else "192.168.1.0/24"
    arguments = get_nmap_args(scan_type)

    output_file = {
        "quick": "resultatrapide.json",
        "standard": "resultatmoyen.json",
        "deep": "resultatapprofondie.json"
    }.get(scan_type, "resultatmoyen.json")

    print(f"[🔍] Scan {scan_type} lancé sur {target}...")

    try:
        # Étape 1 : scan ping
        ping_scan = nmap.PortScanner()
        ping_scan.scan(hosts=target, arguments="-sn")
        live_hosts = ping_scan.all_hosts()

        if not live_hosts:
            print("[⚠️] Aucun hôte détecté sur le réseau.")
            sys.exit(1)

        print(f"[📡] Hôtes actifs détectés : {', '.join(live_hosts)}")

        # Étape 2 : scan ciblé
        scanner = nmap.PortScanner()
        scanner.scan(hosts=" ".join(live_hosts), arguments=arguments)

    except Exception as e:
        print(f"[❌] Erreur lors du scan : {e}")
        sys.exit(1)



    for host in scanner.all_hosts():
        result = {
            "ip": host,
            "os": "Unknown"
        }

        # DNS
        hostnames = scanner[host].get('hostnames', [])
        if hostnames:
            result["hostname"] = hostnames[0].get('name', '')

        if scan_type == "quick":
            scripts = scanner[host].get('hostscript', [])
            for script in scripts:
                if script['id'] == 'nbstat':
                    result["netbios"] = script.get('output', '')

        if scan_type != "quick":
            ports = list(scanner[host].get('tcp', {}).keys())
            result["ports"] = ports
            osmatches = scanner[host].get('osmatch', [])
            osname = osmatches[0].get('name', 'Unknown') if osmatches else 'Unknown'
            result["os"] = osname
            result["role"] = categorize(ports, osname)

        if scan_type == "deep":
            services = []
            for port in ports:
                port_data = scanner[host]['tcp'][port]
                name = port_data.get('name', '')
                product = port_data.get('product', '')
                version = port_data.get('version', '')
                cves = search_cve(product, version)
                service = f"{port}/{name} {product} {version}".strip()
                services.append(service)
            result["services"] = services

        results.append(result)

    # Sauvegarde JSON
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)

    with open("lastscan.txt", "w") as f:
        f.write(output_file)

    # Enregistrement dans la base de données
    try:
        save_scan_entry(scan_type, results)
    except Exception as e:
        print(f"[⚠️] Erreur lors de l'enregistrement en base : {e}")

    print(f"[✅] Scan terminé. Résultats enregistrés dans {output_file} et la base de données.")

if __name__ == "__main__":
    main()
