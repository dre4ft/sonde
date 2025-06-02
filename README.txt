# 📡 Sonde d'Audit Réseau - Projet Python/Flask/Nmap/SQLite

Ce projet transforme un Raspberry Pi en **sonde d’audit réseau** capable de :

- 🔍 Scanner un réseau local avec Nmap (rapide, standard, approfondi)
- 🧠 Classer automatiquement les machines selon leur rôle (poste, imprimante, caméra…)
- 🧾 Sauvegarder les résultats dans :
  - un fichier `.json`
  - une base **SQLite** persistante (`scans.db`)
- 🌐 Offrir une interface web Flask :
  - pour visualiser le **dernier scan**
  - pour accéder à **l’historique complet** avec détails

---

## ⚙️ Structure Technique

### 🗺️ `scan.py` – Script de scan

1. Vérifie les droits `sudo`
2. Ping scan pour détecter les hôtes
3. Scan ciblé via Nmap :
   - `--script nbstat` → rapide
   - `-O -T4` → standard
   - `-A -T4` → approfondi
4. Résolution DNS et NetBIOS
5. Détection de ports, OS, services
6. Catégorisation du rôle de l'hôte
7. Sauvegarde dans :
   - Fichier JSON
   - Base SQLite

### 🗃️ `BD/db.py` – Base de données SQLite

- Utilise **SQLAlchemy**
- Stocke chaque hôte scanné avec :
  - IP, OS, ports, hostname, rôle, services…
- Permet l’historique, les statistiques, les analyses comparatives

### 🌐 `app.py` – Application Flask

- Interface web accessible sur : `http://[IP-RPi]:5000`
- Routes disponibles :
  - `/` → affichage du dernier scan
  - `/scan` → exécution manuelle d’un scan
  - `/historique` → visualisation de tous les scans (via DB)

---

## 🧾 Fichiers générés

- `resultatrapide.json`, `resultatmoyen.json`, `resultatapprofondie.json`
- `lastscan.txt` → contient le nom du dernier scan consulté
- `scans.db` → base SQLite persistante même en cas de redémarrage

---

## 🧠 Fonctionnalités

| Fonction                            | Description |
|-------------------------------------|-------------|
| 🔎 Scan réseau avec Nmap            | Ping + ports + OS + services |
| 🧠 Catégorisation automatique       | Rôle des hôtes selon heuristique |
| 🗃️ Historique des scans en SQLite | Via SQLAlchemy |
| 🌐 Interface web Flask              | Visualisation + interaction |
| 💾 Persistance JSON + DB           | Pour traitement ou export |
| 📊 Préparation à une cartographie  | Intégration future avec `vis-network.js` |

---

## ▶️ Lancer l’application

sudo ~/venv-sonde/bin/python3 app.py

📂 Structure du projet
.
├── scan.py                  # Scanner réseau
├── app.py                   # Interface web
├── BD/
│   └── db.py                # Base de données
├── templates/
│   ├── index.html
│   └── historique.html
├── static/
│   └── icons/
├── resultatrapide.json      # Résultat scan rapide
├── resultatmoyen.json       # Résultat scan standard
├── resultatapprofondie.json # Résultat scan approfondi
├── lastscan.txt             # Nom du dernier fichier
└── scans.db                 # Base SQLite

Évolutions possibles
Cartographie dynamique avec vis-network.js
Export CSV/PDF des scans
Statistiques détaillées (types d’OS, ports exposés, etc.)
Détection de changement entre scans
Interface web sécurisée avec login
Notification email

