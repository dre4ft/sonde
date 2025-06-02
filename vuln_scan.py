import nmap
import json
from vulners import Vulners
import os

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
    import argparse

    parser = argparse.ArgumentParser(description="Scanner de vulnérabilités simple (OpenVAS-like)")
    parser.add_argument("target", help="IP ou nom d'hôte à scanner")
    parser.add_argument("-o", "--output", help="Fichier de sortie JSON", default="resultats.json")

    args = parser.parse_args()
    result = full_scan(args.target)

    # Debug pour vérifier la structure de result
    if result is None:
        print("⚠️ Warning: result is None, forced to empty list")
        result = []
    print(f"DEBUG: result contains {len(result)} entries")

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n✅ Scan terminé. Résultats sauvegardés dans {args.output}")
