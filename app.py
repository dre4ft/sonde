#!/usr/bin/env python3
import os
import json
import subprocess
from flask import Flask, render_template, redirect, url_for, flash, request
from sqlalchemy import func
from sqlalchemy.orm import joinedload
from datetime import datetime
from collections import Counter
from pymongo import MongoClient
from pymongo import MongoClient

from BD.db import init_db, Session, Scan, Service, CVE

# ─── Config MongoDB CVE ─────────────────────────────────────────────────────────
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
CVE_DB    = "cvedb"

mongo_client = MongoClient(MONGO_URI, tz_aware=False)
cve_col      = mongo_client[CVE_DB]["cves"]

# ─── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = 'cle-cle-très-secrète'

def cvss_category(score):
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"

app.jinja_env.filters["cvss_category"] = cvss_category


@app.route("/")
def index():
    default_file = "resultatmoyen.json"
    filename = default_file
    if os.path.exists("lastscan.txt"):
        with open("lastscan.txt", "r", encoding="utf-8") as f:
            filename = f.read().strip()

    data = []
    if os.path.exists(filename):
        try:
            data = json.load(open(filename, encoding="utf-8"))
        except json.JSONDecodeError:
            flash(f"⚠️ Le fichier {filename} est vide ou corrompu.", "warning")

    # On récupère la liste des timestamps pour le sélecteur
    session = Session()
    rows = (
        session.query(
            func.strftime('%Y-%m-%d %H:%M:%S', Scan.timestamp).label('ts')
        )
        .distinct()
        .order_by(Scan.timestamp.desc())
        .all()
    )
    session.close()
    history = [r.ts for r in rows]

    has_ports    = any("ports"    in h for h in data)
    has_role     = any("role"     in h for h in data)
    has_services = any("services" in h for h in data)
    has_hostname = any("hostname" in h for h in data)
    has_netbios  = any("netbios"  in h for h in data)
    has_cves     = any(
        svc.get("cves")
        for host in data
        for svc in host.get("services", [])
    )

    return render_template(
        "index.html",
        data=data,
        filename=filename,
        history=history,
        has_ports=has_ports,
        has_role=has_role,
        has_services=has_services,
        has_hostname=has_hostname,
        has_netbios=has_netbios,
        has_cves=has_cves
    )


@app.route("/show_scan")
def show_scan():
    ts_str = request.args.get("scan_time")
    if not ts_str:
        flash("⚠️ Aucun scan sélectionné.", "warning")
        return redirect(url_for("index"))

    try:
        datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        flash("⚠️ Format de date invalide.", "danger")
        return redirect(url_for("index"))

    session = Session()
    rows = (
        session.query(
            func.strftime('%Y-%m-%d %H:%M:%S', Scan.timestamp).label('ts')
        )
        .distinct()
        .order_by(Scan.timestamp.desc())
        .all()
    )
    history = [r.ts for r in rows]

    scans = (
        session.query(Scan)
               .options(joinedload(Scan.services_rel))
               .filter(
                   func.strftime('%Y-%m-%d %H:%M:%S', Scan.timestamp) == ts_str
               )
               .all()
    )
    session.close()

    if not scans:
        flash(f"⚠️ Aucun scan trouvé à la date {ts_str}.", "warning")
        return redirect(url_for("index"))

    data = []
    for scan in scans:
        ports_raw  = scan.ports or ""
        ports_list = [int(p) for p in ports_raw.split(",") if p.strip()]
        host = {
            "ip":       scan.ip,
            "os":       scan.os,
            "hostname": scan.hostname,
            "netbios":  scan.netbios,
            "ports":    ports_list,
            "role":     scan.role,
            "services": []
        }
        for svc in scan.services_rel:
            info = f"{svc.port}/{svc.name} {svc.product} {svc.version}".strip()
            cves = svc.cves.split(",") if svc.cves else []
            host["services"].append({"info": info, "cves": cves})
        data.append(host)

    has_ports    = any(h["ports"]    for h in data)
    has_role     = any(h["role"]     for h in data)
    has_services = any(h["services"] for h in data)
    has_hostname = any(h["hostname"] for h in data)
    has_netbios  = any(h["netbios"]  for h in data)
    has_cves     = any(c for h in data for c in h["services"] if c["cves"])

    return render_template(
        "index.html",
        data=data,
        filename=None,
        history=history,
        has_ports=has_ports,
        has_role=has_role,
        has_services=has_services,
        has_hostname=has_hostname,
        has_netbios=has_netbios,
        has_cves=has_cves
    )


@app.route("/scan", methods=["POST"])
def scan():
    scan_type = request.form.get("scan_type", "standard")
    target_ip = request.form.get("target_ip", "192.168.1.0/24")
    include_sv = request.form.get("sv") == "on"
    vulners_key = os.environ.get("VULNERS_API_KEY", "")

    cmd = [
        "sudo", "env", f"VULNERS_API_KEY={vulners_key}",
        "/home/etu/venv-sonde/bin/python3",
        "/home/etu/scan.py",
        scan_type,
        target_ip
    ]
    if include_sv:
        cmd.insert(5, "-v")

    try:
        subprocess.run(cmd, check=True)
        flash(f"✅ Scan '{scan_type}' sur {target_ip} terminé.", "success")
    except subprocess.CalledProcessError as e:
        flash(f"❌ Erreur lors du scan : {e}", "danger")

    return redirect(url_for("index"))


@app.route("/historique")
def historique():
    session = Session()
    entries = (
        session.query(Scan)
               .options(joinedload(Scan.services_rel))
               .order_by(Scan.timestamp.desc())
               .all()
    )
    session.close()
    return render_template("historique.html", entries=entries)


@app.route("/vulns")
def vulns():
    """
    Recense les CVEs, filtre sur le scan le plus récent par défaut
    ou sur celui choisi, et n'affiche que les scores stockés en local.
    """
    session = Session()

    # 1) On récupère les dates disponibles
    rows = (
        session.query(
            func.strftime('%Y-%m-%d %H:%M:%S', Scan.timestamp).label('ts')
        )
        .distinct()
        .order_by(Scan.timestamp.desc())
        .all()
    )
    history = [r.ts for r in rows]

    # 2) scan_time = paramètre GET ou le plus récent si absent
    scan_time = request.args.get("scan_time") or (history[0] if history else None)
    selected_scan = scan_time

    # 3) Chargement des services pour ce scan
    if scan_time:
        try:
            datetime.strptime(scan_time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            flash("⚠️ Date de scan invalide.", "warning")
            return redirect(url_for("vulns"))
        services = (
            session.query(Service)
                   .join(Scan)
                   .options(joinedload(Service.scan))
                   .filter(
                       func.strftime('%Y-%m-%d %H:%M:%S', Scan.timestamp) == scan_time
                   )
                   .all()
        )
    else:
        services = session.query(Service).options(joinedload(Service.scan)).all()

    # 4) Comptage et regroupement
    counter, hosts_map = Counter(), {}
    for svc in services:
        ip = svc.scan.ip if svc.scan else None
        for code in (svc.cves.split(",") if svc.cves else []):
            code = code.strip()
            if not code:
                continue
            counter[code] += 1
            hosts_map.setdefault(code, set()).add(ip)

    # 5) Récupération des scores CVSS (local)
    mongo_score = {}
    for cve_id in counter.keys():
        doc = cve_col.find_one(
            {"id": cve_id},
            {"_id": 0, "cvss": 1, "cvss2": 1, "cvss3": 1}
        )
        score = None
        if doc:
            # format ancien
            val = doc.get("cvss")
            if isinstance(val, (int, float)):
                score = val
            elif isinstance(val, dict):
                score = val.get("score")
            # NVD v3
            elif isinstance(doc.get("cvss3"), (int, float)):
                score = doc["cvss3"]
            elif isinstance(doc.get("cvss3"), dict):
                score = doc["cvss3"].get("baseScore") or doc["cvss3"].get("score")
            # fallback v2
            elif isinstance(doc.get("cvss2"), dict):
                score = doc["cvss2"].get("baseScore") or doc["cvss2"].get("score")
        mongo_score[cve_id] = score

    session.close()

    # 6) Préparation du contexte pour le template
    vulns_list = []
    for cve, cnt in counter.most_common():
        hosts = sorted(h for h in hosts_map.get(cve, []) if h)
        vulns_list.append({
            "cve":   cve,
            "score": mongo_score.get(cve),
            "count": cnt,
            "hosts": hosts
        })

    return render_template(
        "vulns.html",
        vulns=vulns_list,
        history=history,
        selected_scan=selected_scan
    )

@app.route('/software')
def software():
    client    = MongoClient(MONGO_URI, tz_aware=False)
    db        = client["zeek"]
    softwares = list(db["software_logs"].find().sort("timestamp", -1))
    return render_template("software.html", softwares=softwares)
    
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
