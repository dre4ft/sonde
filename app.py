from flask import Flask, render_template, redirect, url_for, flash, request
import json, os, subprocess
from sqlalchemy import func
from sqlalchemy.orm import joinedload
from datetime import datetime
from collections import Counter

from BD.db import init_db, Session, Scan, Service, CVE

app = Flask(__name__)
app.secret_key = 'cle-cle-très-secrète'


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
        filename=None,  # on affiche un scan issu de la BD
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
    session = Session()

    # 1) Compte occurrences et hôtes
    services = session.query(Service) \
                      .options(joinedload(Service.scan)) \
                      .all()

    counter   = Counter()
    hosts_map = {}
    for svc in services:
        ip = svc.scan.ip if svc.scan else None
        for code in (svc.cves.split(",") if svc.cves else []):
            code = code.strip()
            if not code:
                continue
            counter[code] += 1
            hosts_map.setdefault(code, set()).add(ip)

    # 2) Récupère tous les CVE en cache pour leur score
    cve_objs  = session.query(CVE).filter(CVE.code.in_(counter.keys())).all()
    score_map = {c.code: c.cvss_score for c in cve_objs}

    session.close()

    # 3) Construit la liste finalisée
    vulns_list = []
    for cve, count in counter.most_common():
        clean_hosts = sorted(x for x in hosts_map[cve] if x)
        vulns_list.append({
            "cve":   cve,
            "score": score_map.get(cve),
            "count": count,
            "hosts": clean_hosts
        })

    return render_template("vulns.html", vulns=vulns_list)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
