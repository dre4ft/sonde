from transformers import pipeline
import json, re
with open("device_patterns.json", "r", encoding="utf-8") as f:
    DEVICE_PATTERNS = json.load(f)

# 1. Instancier la pipeline zero-shot
#    - model : distilbart-mnli-12-1
#    - device=-1 pour CPU
classifier = pipeline(
    "zero-shot-classification",
    model="valhalla/distilbart-mnli-12-1",
    device=-1,
    hypothesis_template="L’appareil décrit est un(e) {}."
)

# 2. Définir les labels possibles
ROLE_LABELS = [
  "Endpoint",     # PC, laptop
  "Smartphone",
  "Service",      # routeur, switch, serveur
  "Maintenance",  # imprimante
  "Surveillance", # caméra
  "IoT",          # thermostat, enceinte connectée…
  "Autre"         # par défaut
]


def classify_roles_local(hosts):
    results = []
    for host in hosts:
        name = ""
        m = re.search(r"hostname=([^,]+)", host)
        if m:
            name = m.group(1).lower()

        # 1) Heuristique par patterns
        for patt, info in DEVICE_PATTERNS.items():
            if patt in name:
                label = info.get("label", info.get("role"))
                role  = info.get("role")
                results.append({
                    "host":  host,
                    "label": label,    # champ "type"
                    "role":  role,     # champ "role" large
                    "score": 1.0
                })
                break
        else:
            # 2) Sinon IA zero-shot sur ROLE_LABELS
            out = classifier(
                sequences=host,
                candidate_labels=ROLE_LABELS,
                multi_label=False
            )
            results.append({
                "host":  host,
                "label": out["labels"][0],   # type "Autre" / "IoT" / ...
                "role":  out["labels"][0] if out["labels"][0] in ROLE_LABELS else "Endpoint",
                "score": out["scores"][0]
            })
    return results


if __name__ == "__main__":
    # Petit test local
    test_hosts = [
        "IP=192.168.1.10, OS=Windows 10, ports=[445], services=[SMB]",
        "IP=192.168.1.20, OS=Linux, ports=[22], services=[ssh]",
        "IP=192.168.1.30, OS=Linux, ports=[161], services=[snmp]"
    ]
    classified = classify_roles_local(test_hosts)
    for c in classified:
        print(f"{c['host']} → {c['label']} ({c['score']:.2f})")
