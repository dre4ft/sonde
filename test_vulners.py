import os
from vulners import Vulners

def test_api_key():
    api_key = os.environ.get("VULNERS_API_KEY")
    if not api_key:
        print("❌ La variable VULNERS_API_KEY n'est pas définie.")
        return

    try:
        vulners_api = Vulners(api_key)
        print("✅ Client Vulners initialisé.")
        result = vulners_api.search("nginx 1.18")
        if result:
            print(f"🔎 {len(result)} résultats pour « nginx 1.18 »")
            print("🔗 Exemple de CVE :", result[0].get("id", "inconnu"))
        else:
            print("⚠️ Aucun résultat trouvé.")
    except Exception as e:
        print(f"❌ Erreur avec l'API : {e}")

if __name__ == "__main__":
    test_api_key()
