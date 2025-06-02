import os
import json
import sqlite3
import sys
from pathlib import Path


def create_tables(conn):
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cve (
            id TEXT PRIMARY KEY,
            title TEXT,
            description TEXT,
            severity TEXT,
            baseScore REAL,
            vector TEXT,
            assigner TEXT,
            datePublished TEXT,
            dateUpdated TEXT
        )
    ''')
    conn.commit()


def extract_cve_data(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        cve_id = Path(filepath).stem

        cna = data.get("containers", {}).get("cna", {})

        title = cna.get("title", "")
        description = ""
        for desc in cna.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        severity = None
        base_score = None
        vector = None
        metrics = cna.get("metrics", [])
        for m in metrics:
            cvss = m.get("cvssV3_1")
            if cvss:
                severity = cvss.get("baseSeverity")
                base_score = cvss.get("baseScore")
                vector = cvss.get("vectorString")
                break

        metadata = data.get("cveMetadata", {})
        assigner = metadata.get("assignerShortName", "")
        datePublished = metadata.get("datePublished", "")
        dateUpdated = metadata.get("dateUpdated", "")

        return (
            cve_id, title, description, severity,
            base_score, vector, assigner,
            datePublished, dateUpdated
        )

    except Exception as e:
        print(f"[❌] Erreur lecture fichier {filepath}: {e}")
        return None


def import_json_folder(folder_path, db_path="cve_data.db"):
    conn = sqlite3.connect(db_path)
    create_tables(conn)

    total = 0
    inserted = 0

    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.lower().endswith(".json"):
                total += 1
                filepath = os.path.join(root, file)
                cve_data = extract_cve_data(filepath)
                if not cve_data:
                    continue

                try:
                    conn.execute('''
                        INSERT OR REPLACE INTO cve (
                            id, title, description, severity,
                            baseScore, vector, assigner,
                            datePublished, dateUpdated
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', cve_data)
                    inserted += 1
                except Exception as e:
                    print(f"[⚠️] Erreur insertion {file} : {e}")

    conn.commit()
    conn.close()
    print(f"[✅] {inserted}/{total} fichiers insérés dans la base '{db_path}'.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage : python import_cve_json_to_sqlite.py <dossier_des_jsons> [base.sqlite]")
        sys.exit(1)

    folder = sys.argv[1]
    db_file = sys.argv[2] if len(sys.argv) > 2 else "cve_data.db"

    import_json_folder(folder, db_file)
