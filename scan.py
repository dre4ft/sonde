import nmap
import json
import os
import sys
import argparse
import vulners

from BD.db import save_scan_entry

# On récupère la clé API Vulners dans la variable d'environnement
api_key = os.environ.get("VULNERS_API_KEY")


def get_nmap_args(scan_type, vuln):
    """
    Retourne les arguments à passer à nmap en fonction du type de scan
    et de l'activation ou non de la recherche de vulnérabilités (-sV).
    """
    if scan_type == "quick":
        return "-sV" if vuln else "--script nbstat"
    elif scan_type == "standard":
        # si vuln=True, on force -sV pour récupérer produit/version
        return "-O -T4 -sV" if vuln else "-O -T4"
    elif scan_type == "deep":
        return "-A -T4"
    else:
        return "-O -T4"


def categorize(ports, osname):
    """
    Catégorisation sommaire en fonction des ports ouverts et du nom d'OS.
    """
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


def sort_cves_by_year(cves):
    """
    Trie une liste de codes CVE (ex. 'CVE-2023-1234') par année ascendante.
    """
    def extract_year(cve_code):
        try:
            return int(cve_code.split('-')[1])
        except (IndexError, ValueError):
            return 0

    return sorted(cves, key=extract_year)


def search_cve(product, version):
    """
    Interroge l'API Vulners pour le couple (product, version).
    Si pas de clé API ou erreur, renvoie [].
    """
    if not product or not version:
        return []

    if not api_key:
        print("⚠️ VULNERS_API_KEY non définie, on passe la recherche de CVE.")
        return []

    try:
        vulners_api = vulners.Vulners(api_key)
    except Exception as e:
        print(f"⚠️ Erreur initialisation Vulners API : {e}")
        return []

    query = f"{product} {version}"
    print(f"🔎 Recherche de vulnérabilités pour « {query} » …")
    try:
        results = vulners_api.search(query)
        cves = []
        for r in results:
            if "cvelist" in r:
                cves += r["cvelist"]
        # On enlève les doublons et on trie
        return list(set(sort_cves_by_year(cves)))
    except Exception as e:
        print(f"⚠️ Erreur recherche CVE : {e}")
        return []


def main():
    parser = argparse.ArgumentParser(
        description="Scanner de réseau avec détection optionnelle des vulnérabilités."
    )
    parser.add_argument(
        "scan_type", choices=["quick", "standard", "deep"], help="Type de scan"
    )
    parser.add_argument("target", help="Plage d'IP ou IP unique à scanner")
    parser.add_argument(
        "-v", "--vuln", action="store_true", help="Activer la recherche de vulnérabilités"
    )
    args = parser.parse_args()

    # Nécessite d'être root pour un scan -sn / -O etc.
    if os.geteuid() != 0:
        print("[❌] Ce script doit être exécuté avec sudo.")
        sys.exit(1)

    arguments = get_nmap_args(args.scan_type, args.vuln)
    output_file = {
        "quick": "resultatrapide.json",
        "standard": "resultatmoyen.json",
        "deep": "resultatapprofondie.json",
    }.get(args.scan_type, "resultatmoyen.json")

    print(f"[🔍] Scan {args.scan_type} lancé sur {args.target}…")

    try:
        # Étape 1 : ping-scan pour détecter les hôtes actifs
        ping_scan = nmap.PortScanner()
        ping_scan.scan(hosts=args.target, arguments="-sn")
        live_hosts = ping_scan.all_hosts()

        if not live_hosts:
            print("[⚠️] Aucun hôte détecté sur le réseau.")
            sys.exit(1)

        print(f"[📡] Hôtes actifs détectés : {', '.join(live_hosts)}")

        # Étape 2 : scan ciblé avec les arguments définis
        scanner = nmap.PortScanner()
        scanner.scan(hosts=" ".join(live_hosts), arguments=arguments)

    except Exception as e:
        print(f"[❌] Erreur lors du scan : {e}")
        sys.exit(1)

    results = []

    for host in scanner.all_hosts():
        result = {"ip": host, "os": "Unknown"}

        # Résolution DNS
        hostnames = scanner[host].get("hostnames", [])
        if hostnames:
            result["hostname"] = hostnames[0].get("name", "")

        # Si scan rapide ("quick"), on récupère uniquement netbios via nbstat
        if args.scan_type == "quick":
            scripts = scanner[host].get("hostscript", [])
            for script in scripts:
                if script.get("id") == "nbstat":
                    result["netbios"] = script.get("output", "")

        # Si scan standard ou approfondi, on récupère ports, OS, rôle, puis services
        if args.scan_type != "quick":
            ports = list(scanner[host].get("tcp", {}).keys())
            result["ports"] = ports

            osmatches = scanner[host].get("osmatch", [])
            osname = osmatches[0].get("name", "Unknown") if osmatches else "Unknown"
            result["os"] = osname
            result["role"] = categorize(ports, osname)

            # Construire la liste "services" dans tous les cas
            services = []
            for port in ports:
                port_data = scanner[host]["tcp"][port]
                name = port_data.get("name", "")
                product = port_data.get("product", "")
                version = port_data.get("version", "")

                # Si on a demandé la recherche de vulnérabilités, on lève la liste de CVEs
                if args.vuln:
                    cves = search_cve(product, version)
                else:
                    cves = []

                services.append({
                    "port": port,
                    "name": name,
                    "product": product,
                    "version": version,
                    "cves": cves
                })

            result["services"] = services

        results.append(result)

    # Sauvegarde JSON
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    # On écrit aussi le nom du dernier fichier dans lastscan.txt
    with open("lastscan.txt", "w", encoding="utf-8") as f:
        f.write(output_file)

    # Enregistrement en base de données
    try:
        save_scan_entry(args.scan_type, results)
    except Exception as e:
        print(f"[⚠️] Erreur lors de l'enregistrement en base : {e}")

    print(f"[✅] Scan terminé. Résultats enregistrés dans {output_file} et la base de données.")


if __name__ == "__main__":
    main()
