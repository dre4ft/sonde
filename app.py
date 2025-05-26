from flask import Flask, render_template, redirect, url_for, flash
import json
import os
import subprocess

app = Flask(__name__)
app.secret_key = 'cle-ultra-secrete'  # Nécessaire pour les messages flash

@app.route("/")
def index():
    if not os.path.exists("results.json"):
        data = []
    else:
        with open("results.json") as f:
            data = json.load(f)
    return render_template("index.html", data=data)

@app.route("/scan")
def scan():
    try:
        subprocess.run(["sudo", "python3", "scan.py"], check=True)
        flash("✅ Scan terminé avec succès.", "success")
    except subprocess.CalledProcessError as e:
        flash(f"❌ Erreur lors du scan : {e}", "danger")
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
