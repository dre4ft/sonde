import nmap
import json
import os
import sys

def get_nmap_args(scan_type):
    if scan_type == "quick":
        return "-sn -T4 --script nbstat"
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

def main():
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

    scanner = nmap.PortScanner()
    print(f"[🔍] Lancement du scan ({scan_type}) sur {target} avec les arguments : {arguments}")

    try:
        scanner.scan(hosts=target, arguments=arguments)
    except Exception as e:
        print(f"[❌] Erreur lors du scan : {e}")
        sys.exit(1)

    results = []

for host in scanner.all_hosts():
    print(f"[🧪] Hôtes détectés : {scanner.all_hosts()}")

    result = {
        "ip": host,
        "os": "Unknown"
    }

    # Ajout du nom DNS pour tous les scans
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
            service = f"{port}/{name} {product} {version}".strip()
            services.append(service)
        result["services"] = services

    results.append(result)


    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)

    with open("lastscan.txt", "w") as f:
        f.write(output_file)

    print(f"[✅] Scan terminé. Résultats enregistrés dans {output_file}")

if __name__ == "__main__":
    main()
