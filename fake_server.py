from flask import Flask, request, send_from_directory, abort
import os

app = Flask(__name__)
PORT = 8080

# Dossier public simulé
WEB_ROOT = os.path.abspath("www")

@app.route("/")
def index():
    return """
    <h1>Welcome to vulnerable Apache 2.4.49</h1>
    <p>This is a demo page simulating a vulnerable version of Apache.</p>
    """

# Vulnérabilité simulée de type path traversal
@app.route("/cgi-bin/<path:filename>")
def vulnerable_cgi(filename):
    try:
        # Simulation d'un comportement vulnérable : path traversal
        filepath = os.path.join("/", filename)  # dangereux si pas nettoyé
        if ".." in filename:
            # Simuler l'accès interdit mais réussi
            return f"Access to {filepath} successful (simulated path traversal)", 200
        return send_from_directory(WEB_ROOT, filename)
    except Exception as e:
        return f"Error: {str(e)}", 500

# Réponse pour nmap version detection
@app.after_request
def add_server_header(response):
    response.headers["Server"] = "Apache/2.4 (Unix)"
    return response

if __name__ == "__main__":
    os.makedirs(WEB_ROOT, exist_ok=True)
    with open(os.path.join(WEB_ROOT, "index.html"), "w") as f:
        f.write("<h1>Fake Apache Homepage</h1>")
    
    print(f"🚀 Fake Apache server (vulnerable) running on http://localhost:{PORT}")
    app.run(host="127.0.0.1", port=PORT)
