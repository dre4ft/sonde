from flask import Flask, render_template
import json
import os

app = Flask(__name__)

@app.route("/")
def index():
    if not os.path.exists("results.json"):
        return "<h2>Aucun résultat disponible. Lancez un scan d'abord.</h2>"
    
    with open("results.json") as f:
        data = json.load(f)
    return render_template("index.html", data=data)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

