#!/usr/bin/env python3
import os, sys
import json
import subprocess
import threading
import io
from io import BytesIO
from datetime import datetime
from collections import Counter
from weasyprint import HTML
from flask import (
    Flask, render_template, redirect, url_for, flash, request, jsonify, send_file
)
from sqlalchemy import func
from sqlalchemy.orm import joinedload
from pymongo import MongoClient

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

from ai_local import classify_scan_results

from BD.scan_db import init_db, Session, Scan, Service, CVE
from BD.packet_db import (
    init_packet_db, Packet, SessionPackets, KO_packet, get_ko_packets
)
from capture import start_capture, stop_capture, get_rules
from rule_engine import RulesEngine

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
    has_type     = any("type" in h or "device_type" in h for h in data)
    has_ai = any("ai_score" in h for h in data)

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
        has_cves=has_cves,
        has_type=has_type,
        has_ai=has_ai
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
            "services": [],
            "type": getattr(scan, "device_type", ""),
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
    has_type     = any("type" in h for h in data)
    has_ai = False  # Les anciens scans n'ont pas d'IA

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
        has_cves=has_cves,
        has_type=has_type,
        has_ai=has_ai
    )


@app.route("/scan", methods=["POST"])
def scan():
    scan_type = request.form.get("scan_type", "standard")
    target_ip = request.form.get("target_ip", "192.168.1.0/24")
    include_sv = request.form.get("sv") == "on"
    include_ai = request.form.get("ai") == "on"
    
    # Déterminer le bon chemin Python et script
    # venv_python = os.environ.get("VIRTUAL_ENV")
    # if venv_python:
    #     python_path = os.path.join(venv_python, "bin", "python3")
    # else:
    #     python_path = "/usr/bin/python3"
    python_path = sys.executable
    
    # Chemin du script scan.py (dans le même répertoire que app.py)
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan.py")
    
    cmd = [
        "sudo", "-E",
        python_path,
        script_path,
        scan_type,
        target_ip
    ]
    
    if include_sv:
        cmd.append("-v")
    if include_ai:
        cmd.append("-a")

    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        flash(f"✅ Scan '{scan_type}' sur {target_ip} terminé.", "success")
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr if e.stderr else str(e)
        flash(f"❌ Erreur lors du scan : {error_msg}", "danger")
    except Exception as e:
        flash(f"❌ Erreur inattendue : {str(e)}", "danger")

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

@app.route("/map")
def carte():
    # comme dans index(), on relaie les mêmes données
    filename = "lastscan.txt"
    # … code pour charger `data` depuis le JSON …
    return render_template("map.html", data=data)


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
    
@app.route("/ai_stats") 
def ai_stats(): 
    """ 
    Statistiques sur les classifications IA. 
    Par défaut on affiche le scan le plus récent, 
    ou celui passé en GET ?scan_time=YYYY-mm-dd HH:MM:SS. 
    """ 
    session = Session() 
 
    # --- 1. quel scan veut-on ? -------------------------------------------- 
    from sqlalchemy import func 
    scan_time = request.args.get("scan_time") 
    base_q = session.query(Scan).filter(Scan.device_type.isnot(None)) 
 
    if scan_time: 
        base_q = base_q.filter( 
            func.strftime('%Y-%m-%d %H:%M:%S', Scan.timestamp) == scan_time 
        ) 
    else: 
        latest_ts = session.query(func.max(Scan.timestamp)).scalar() 
        base_q = base_q.filter(Scan.timestamp == latest_ts) 
 
    scans = base_q.all()
    
    # Calculer les stats
    type_counts = {}
    confidence_by_type = {}
    
    for scan in scans:
        device_type = scan.device_type or "Unknown"
        # Score : on ignore les None, on accepte 0.0 comme valeur valide
        raw_score = getattr(scan, "ai_score", None) 
        try: 
            ai_score = float(raw_score) if raw_score is not None else None 
        except (ValueError, TypeError): 
            ai_score = None        # n'entre pas dans les stats
        
        if device_type not in type_counts:
            type_counts[device_type] = 0
            confidence_by_type[device_type] = []
        
        type_counts[device_type] += 1
        if ai_score is not None:
            confidence_by_type[device_type].append(ai_score)
    
    # Moyennes de confiance
    avg_confidence = {}
    for dtype, scores in confidence_by_type.items():
        avg_confidence[dtype] = sum(scores) / len(scores) if scores else 0
    
    # Convertir les valeurs de confiance en pourcentages pour le template
    avg_confidence_percent = [v * 100 for v in avg_confidence.values()]
    
    session.close()
    
    return render_template(
        "ai_stats.html",
        type_counts=type_counts,
        avg_confidence=avg_confidence,
        avg_confidence_percent=avg_confidence_percent,
        total_classified=sum(type_counts.values())
    )

@app.route("/report")
def download_report():
    # 1) Récupérer le paramètre et valider
    scan_time = request.args.get("scan_time")
    if not scan_time:
        flash("⚠️ Aucun scan sélectionné pour le rapport.", "warning")
        return redirect(url_for("vulns"))
    try:
        dt = datetime.strptime(scan_time, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        flash("⚠️ Format de date invalide pour le rapport.", "danger")
        return redirect(url_for("vulns"))

    # 2) Charger le scan et ses services depuis SQLite
    session = Session()
    scans = (
        session.query(Scan)
               .options(joinedload(Scan.services_rel))
               .filter(
                   func.strftime('%Y-%m-%d %H:%M:%S', Scan.timestamp) == scan_time
               )
               .all()
    )
    session.close()
    if not scans:
        flash(f"⚠️ Aucun scan trouvé pour la date {scan_time}.", "warning")
        return redirect(url_for("vulns"))

    # 3) Préparer les données pour le template
    # --- liste des hôtes et services ---
    hosts = []
    for scan in scans:
        ports = [int(p) for p in (scan.ports or "").split(",") if p.strip()]
        host = {
            "ip":       scan.ip,
            "os":       scan.os,
            "hostname": scan.hostname or "—",
            "ports":    ports,
            "role":     scan.role,
            "services": []
        }
        for svc in scan.services_rel:
            info = f"{svc.port}/{svc.name} {svc.product} {svc.version}".strip()
            host["services"].append({
                "info":    info,
                "port":    svc.port,
                "name":    svc.name,
                "product": svc.product,
                "version": svc.version,
                "cves":    [c.strip() for c in (svc.cves or "").split(",") if c.strip()]
            })
        hosts.append(host)

    # --- résumé des vulnérabilités (CVE) ---
    counter, hosts_map = Counter(), {}
    for h in hosts:
        for svc in h["services"]:
            for cve_id in svc["cves"]:
                counter[cve_id] += 1
                hosts_map.setdefault(cve_id, set()).add(h["ip"])

    # on peut ne pas charger les scores si vous le souhaitez,
    # ou faire une requête Mongo comme dans /vulns.
    vulns = []
    for cve, cnt in counter.most_common():
        vulns.append({
            "cve":     cve,
            "count":   cnt,
            "hosts":   sorted(hosts_map[cve])
        })

    # 4) Rendu HTML du rapport
    html_out = render_template(
        "report.html",
        scan_time=scan_time,
        hosts=hosts,
        vulns=vulns
    )

    # 5) Génération du PDF en mémoire
    pdf = HTML(string=html_out, base_url=request.base_url).write_pdf()

    # 6) Envoi du PDF
    pdf_filename = f"rapport_{dt.strftime('%Y-%m-%d_%H_%M_%S')}.pdf"
    return send_file(
        BytesIO(pdf),
        as_attachment=True,
        download_name=pdf_filename,
        mimetype="application/pdf"
    )

# ---- Scan passif ----
@app.route("/passive_scan")
def passive_scan():
    return render_template("passive_scan.html")

@app.route("/api/packets/")
def api_get_packets():
    session = SessionPackets()
    try:
        packets = session.query(Packet).order_by(Packet.id.desc()).limit(100).all()
        results = []
        for p in packets:
            results.append({
                "id": p.id,
                "timestamp": p.timestamp.isoformat() if p.timestamp else None,
                "src_ip": p.src_ip,
                "dst_ip": p.dst_ip,
                "protocol": p.protocol,
                "src_port": p.src_port,
                "dst_port": p.dst_port,
                "raw": p.raw,
                "rule_matched": p.rule_matched.lower() == "true" if isinstance(p.rule_matched, str) else bool(p.rule_matched)
            })
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


@app.route("/api/ko_packets/")
def api_get_ko_packets(): 
    try:
        ko_packets = get_ko_packets()
        if not ko_packets:
            return jsonify([]), 200  # Retourne une liste vide au lieu d'une erreur 404

        results = []
        for ko in ko_packets:
            pkt = ko.packet
            results.append({
                "id": ko.id,
                "rules": ko.rules,
                "packet": {
                    "id": pkt.id,
                    "timestamp": pkt.timestamp.isoformat(),
                    "src_ip": pkt.src_ip,
                    "dst_ip": pkt.dst_ip,
                    "protocol": pkt.protocol,
                    "src_port": pkt.src_port,
                    "dst_port": pkt.dst_port,
                    "raw": pkt.raw,
                    "rule_matched": pkt.rule_matched,
                }
            })
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route('/api/download_ko_packets_pdf')
def download_ko_packets_pdf():
    ko_packets = get_ko_packets()
    if not ko_packets:
        return jsonify({"error": "Aucun paquet KO trouvé"}), 404    

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # 🔹 Titre principal
    title = Paragraph("Récapitulatif des paquets non conformes", styles['Title'])
    subtitle = Paragraph(
        "Ce document contient la liste des paquets réseau ayant enfreint une ou plusieurs règles de sécurité définies par la sonde d’audit.",
        styles['Normal']
    )
    elements.extend([title, Spacer(1, 12), subtitle, Spacer(1, 24)])

    # 🔹 Données du tableau
    headers = ["ID", "Règle", "Horodatage", "IP source", "IP destination", "Protocole"]
    data = [headers]

    for pkt in ko_packets:
        try:
            rule_desc = ""
            if hasattr(pkt, 'rule'):
                rule_desc = pkt.rule
            elif hasattr(pkt, 'rules'):
                try:
                    rules_obj = json.loads(pkt.rules)
                    rule_desc = rules_obj.get('description', str(pkt.rules))
                except Exception:
                    rule_desc = str(pkt.rules)

            packet = pkt.packet
            data.append([
                str(pkt.id),
                rule_desc[:40],
                packet.timestamp.strftime('%Y-%m-%d %H:%M:%S') if hasattr(packet, 'timestamp') and packet.timestamp else "",
                getattr(packet, 'src_ip', ""),
                getattr(packet, 'dst_ip', ""),
                getattr(packet, 'protocol', "")
            ])
        except Exception as e:
            print("Erreur lors de l'ajout du paquet au PDF:", e)

    # 🔹 Création du tableau stylisé
    table = Table(data, colWidths=[40, 140, 110, 90, 90, 60])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('GRID', (0, 0), (-1, -1), 0.25, colors.black),
    ]))

    elements.append(table)
    doc.build(elements)

    # 🔹 Nom du fichier avec date
    date_str = datetime.now().strftime("%d-%m-%Y")
    filename = f"paquets_KO_{date_str}.pdf"

    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype='application/pdf'
    )





@app.route("/api/add_rules", methods=["POST"])
def add_rules():
    try:
        RULES_FILE="rules.json"
        # On récupère la donnée brute envoyée (en texte)
        raw_data = request.get_data(as_text=True).strip()

        # Pour que ce soit un JSON valide de liste, on ajoute des crochets autour
        # Exemple : raw_data = '{...}, {...}' -> '[{...}, {...}]'
        try:
            new_rules_data = json.loads(f"[{raw_data}]")
        except json.JSONDecodeError as e:
            return jsonify({"detail": f"Erreur JSON : {str(e)}"}), 400

        if not isinstance(new_rules_data, list):
            return jsonify({"detail": "Une liste de règles est requise."}), 400

        # Charger les règles existantes
        if not os.path.exists(RULES_FILE):
            rules = {"rules": []}
        else:
            with open(RULES_FILE, "r") as f:
                rules = json.load(f)

        existing_ids = [rule.get("id", 0) for rule in rules["rules"]]
        next_id = max(existing_ids, default=0) + 1

        added_rules = []

        for rule_data in new_rules_data:
            if "description" not in rule_data:
                return jsonify({"detail": "Chaque règle doit contenir un champ 'description'."}), 400

            new_rule = {
                "id": next_id,
                "description": rule_data["description"],
                "src_ip": rule_data.get("src_ip", "0.0.0.0/0"),
                "dst_ip": rule_data.get("dst_ip", "0.0.0.0/0"),
                "protocol": rule_data.get("protocol", "TCP"),
                "dst_port": rule_data.get("dst_port"),
                "src_port": rule_data.get("src_port"),
                "action": rule_data.get("action", "deny"),
            }

            # Supprimer les champs None
            new_rule = {k: v for k, v in new_rule.items() if v is not None}

            rules["rules"].append(new_rule)
            added_rules.append(new_rule)
            next_id += 1

        # Sauvegarder
        with open(RULES_FILE, "w") as f:
            json.dump(rules, f, indent=2)
        

        return jsonify({"message": f"{len(added_rules)} règles ajoutées avec succès.", "rules": added_rules}), 200

    except Exception as e:
        return jsonify({"detail": f"Erreur serveur : {str(e)}"}), 500


@app.route("/api/rules/")
def api_get_rules():
    return  get_rules()

@app.route("/api/start_capture", methods=["POST"])
def api_start_capture():
    data = request.get_json()
    interface = data.get("interface") if data else None
    started = start_capture(interface)
    if not started:
        return jsonify({"error": "Capture déjà en cours"}), 400
    return jsonify({"status": "capture démarrée", "interface": interface})

@app.route("/api/stop_capture", methods=["POST"])
def api_stop_capture():
    stop_capture()
    return jsonify({"status": "capture arrêtée"})


if __name__ == "__main__":
    init_db()
    init_packet_db()
    app.run(host="0.0.0.0", port=5000)
