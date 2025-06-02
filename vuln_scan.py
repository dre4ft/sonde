import nmap
import json
from vulners import Vulners
import os
import argparse
from datetime import datetime

api_key = os.environ.get("VULNERS_API_KEY")




def scan_ports(target):
    print(f"🔍 Scan des ports sur {target} ...")
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-sV')  # Scan TCP + détection version
    results = []

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                service = scanner[host][proto][port]
                results.append({
                    'host': host,
                    'port': port,
                    'name': service['name'],
                    'product': service.get('product', ''),
                    'version': service.get('version', ''),
                    'extrainfo': service.get('extrainfo', '')
                })
    return results

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
        return list(set(cves))
    except Exception as e:
        print("⚠️ Erreur recherche CVE:", e)
        return []

def full_scan(target):
    ports = scan_ports(target)
    for service in ports:
        product = service['product']
        version = service['version']
        service['cves'] = search_cve(product, version)
    return ports  # <-- IMPORTANT : retourne les résultats scannés

if __name__ == "__main__":
    

    parser = argparse.ArgumentParser(description="Scanner de vulnérabilités simple (OpenVAS-like)")
    parser.add_argument("target", help="IP ou nom d'hôte à scanner")

    args = parser.parse_args()
    result = full_scan(args.target)

    # Crée le dossier export s'il n'existe pas
    export_dir = "export"
    os.makedirs(export_dir, exist_ok=True)

    # Génère le nom de fichier
    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan-{args.target}-{now}.json"
    filepath = os.path.join(export_dir, filename)

    # Debug
    if result is None:
        print("⚠️ Warning: result is None, forced to empty list")
        result = []
    print(f"DEBUG: result contient {len(result)} entrées")

    # Sauvegarde JSON
    with open(filepath, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n✅ Scan terminé. Résultats sauvegardés dans {filepath}")
