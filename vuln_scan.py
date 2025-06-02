import subprocess
import xmltodict
import requests
import json
from datetime import datetime
import os
import sqlite3

def scan_ports_and_services(ip):
    print(f"🔍 Scan en cours sur {ip} (ports + version)...")
    cmd = ["nmap", "-sV", "-oX", "-", ip]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout


def parse_nmap_xml(xml_data):
    parsed = xmltodict.parse(xml_data)
    results = []

    try:
        host = parsed["nmaprun"].get("host", None)
        if not host:
            print("Aucun hôte détecté dans le scan.")
            return []

        ports = host.get("ports", {}).get("port", [])
        if isinstance(ports, dict):  # Un seul port
            ports = [ports]

        for port in ports:
            state = port.get("state", {}).get("@state", "")
            if state != "open":
                continue

            service_info = port.get("service", {})
            product = service_info.get("@product", "")
            version = service_info.get("@version", "")
            app = product if product else service_info.get("@name", "unknown")

            results.append({
                "port": port.get("@portid"),
                "protocol": port.get("@protocol"),
                "name": service_info.get("@name", "unknown"),
                "product": app,
                "version": version,
                "cves": []  # Remplissage plus tard
            })
    except Exception as e:
        print("❌ Erreur lors du parsing XML:", e)
    return results




def search_cve_local(product, version, db_path="cve_data.db"):
    if not product:
        return []

    print(f"🔍 Recherche locale dans {db_path} pour : {product} {version}")

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Requête : vérifie si le champ 'product' ou 'vendor' correspond au produit fourni
        # On vérifie aussi si la version actuelle est inférieure à la version affectée
        cursor.execute('''
            SELECT DISTINCT cve.id, cve.title, cve.description, cve.severity, cve.baseScore
            FROM cve
            JOIN affected_products ON cve.id = affected_products.cve_id
            WHERE (
                LOWER(affected_products.product) = LOWER(?) 
                OR LOWER(affected_products.vendor) = LOWER(?) 
                OR (LOWER(affected_products.vendor) = LOWER(?) AND LOWER(affected_products.product) = LOWER(?))
            )
            AND (
                affected_products.version = ? 
                OR ? < affected_products.less_than
            )
        ''', (product, product, product, product, version, version))

        results = cursor.fetchall()
        conn.close()

        cve_list = []
        for row in results:
            cve_id, title, description, severity, score = row
            cve_list.append({
                "id": cve_id,
                "title": title,
                "description": description,
                "severity": severity,
                "score": score
            })

        return cve_list

    except Exception as e:
        print("⚠️ Erreur lors de l’interrogation de la base :", e)
        return []

def search_cve_nvd(product, version):
    if not product:
        return []

    query = f"{product} {version}".strip().replace(" ", "+")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=5"
    headers = {"User-Agent": "CVE-Scanner/1.0"}

    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code != 200:
            return []

        data = response.json()
        cves = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            description = cve.get("descriptions", [{}])[0].get("value", "")
            if cve_id:
                cves.append({
                    "id": cve_id,
                    "description": description
                })

        return cves

    except Exception as e:
        print(f"[⚠️] Erreur NVD pour {product} {version} :", e)
        return []

def export_to_json(scan_data, ip):
    now = datetime.now()
    timestamp = now.strftime("%Y%m%d-%H%M%S")
    filename = f"scan-{ip}-{timestamp}.json"
    output = {
        "ip": ip,
        "timestamp": now.isoformat(),
        "results": scan_data
    }

    os.makedirs("exports", exist_ok=True)
    filepath = os.path.join("exports", filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)

    print(f"\n📁 Résultat exporté dans : {filepath}")


def main(ip):
    xml_data = scan_ports_and_services(ip)
    services = parse_nmap_xml(xml_data)

    if not services:
        print("🚫 Aucun service détecté ou hôte injoignable.")
        return

    for s in services:
        print(f"\n🟢 Port {s['port']}/{s['protocol']} - {s['name']}: {s['product']} {s['version']}")
        vulns = search_cve_local(s["product"], s["version"])
        s["cves"] = vulns
        if vulns:
            for vuln in vulns:
                print(f"\n🛡️ {vuln['id']} ({vuln['severity']}) - Score {vuln['score']}")
                print(f"  ➤ {vuln['title']}")
                print(f"  {vuln['description'][:200]}...")
        else:
            cves = search_cve_nvd(s["product"], s["version"])
            s["cves"] = cves
            if cves:
                print("   ⚠️ CVEs trouvées :")
                for cve in cves:
                    print(f"     - {cve['id']}: {cve['description'][:100]}...")
            else:
                print("   ✅ Aucun CVE connu trouvé.")


    export_to_json(services, ip)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Scan actif + détection de CVE (via NVD) + export JSON")
    parser.add_argument("ip", help="Adresse IP cible")
    args = parser.parse_args()

    main(args.ip)
