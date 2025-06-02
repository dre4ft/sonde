from vulners import Vulners
import os

api_key = os.environ.get("VULNERS_API_KEY")


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

