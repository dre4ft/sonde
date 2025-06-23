from transformers import pipeline

# 1. Instancier la pipeline zero-shot
#    - model : distilbart-mnli-12-1
#    - device=-1 pour CPU
classifier = pipeline(
    "zero-shot-classification",
    model="valhalla/distilbart-mnli-12-1",
    device=-1
)

# 2. Définir les labels possibles
ROLE_LABELS = ["Endpoint", "Service", "Maintenance", "Surveillance"]

def classify_roles_local(hosts):
    """
    Pour chaque host (chaîne descriptive), renvoie son rôle et le score associé.
    hosts: list[str], ex: "IP=192.168.1.5, OS=Linux, ports=[22,80], services=[ssh,http]"
    return: list[dict] avec {'host': ..., 'label': ..., 'score': ...}
    """
    results = []
    for host in hosts:
        out = classifier(
            sequences=host,
            candidate_labels=ROLE_LABELS,
            multi_label=False  # on veut un seul rôle par machine
        )
        # out = {'labels': [...], 'scores':[...], ...}
        results.append({
            "host": host,
            "label": out["labels"][0],
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
