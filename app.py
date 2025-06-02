from flask import Flask, render_template, redirect, url_for, flash, request
import json, os, subprocess
from BD.db import init_db, Session, Scan

app = Flask(__name__)
app.secret_key = 'cle-ultra-secrete'

# === ROUTES PRINCIPALES ===

@app.route("/")
def index():
    default_file = "resultatmoyen.json"
    filename = default_file
    if os.path.exists("lastscan.txt"):
        with open("lastscan.txt", "r") as f:
            filename = f.read().strip()

    data = []
    if os.path.exists(filename):
        with open(filename) as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                flash(f"⚠️ Le fichier {filename} est vide ou corrompu.", "warning")

    has_ports = any("ports" in h for h in data)
    has_role = any("role" in h for h in data)
    has_services = any("services" in h for h in data)
    has_hostname = any("hostname" in h for h in data)
    has_netbios = any("netbios" in h for h in data)

    return render_template("index.html", data=data,
                           has_ports=has_ports,
                           has_role=has_role,
                           has_services=has_services,
                           has_hostname=has_hostname,
                           has_netbios=has_netbios,
                           filename=filename)

@app.route("/scan", methods=["POST"])
def scan():
    scan_type = request.form.get("scan_type", "standard")
    target_ip = request.form.get("target_ip", "192.168.1.0/24")
    try:
        subprocess.run([
            "sudo",
            "/home/etu/venv-sonde/bin/python3",
            "/home/etu/scan.py",
            scan_type,
            target_ip
        ], check=True)
        flash(f"✅ Scan '{scan_type}' sur {target_ip} terminé avec succès.", "success")
    except subprocess.CalledProcessError as e:
        flash(f"❌ Erreur lors du scan : {e}", "danger")
    return redirect(url_for('index'))

@app.route("/map")
def map_view():
    try:
        with open("results.json") as f:
            data = json.load(f)
    except Exception:
        data = []
    return render_template("map.html", data=data)

@app.route("/historique")
def historique():
    session = Session()
    entries = session.query(Scan).order_by(Scan.timestamp.desc()).all()
    return render_template("historique.html", entries=entries)

# === LANCEMENT ===
if __name__ == "__main__":
    init_db()  # assure que la base est bien initialisée
    app.run(host="0.0.0.0", port=5000)
