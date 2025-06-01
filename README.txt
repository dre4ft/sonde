# 🚀 Sonde d’Audit Réseau

Ce projet propose une sonde réseau légère, déployable sur un Raspberry Pi, permettant de scanner un réseau local, identifier les machines, les classifier par rôle, et visualiser les résultats via une interface web intuitive.

---

## 🌟 Fonctionnalités principales

* ✅ Scan rapide, standard ou approfondi avec Nmap
* ✅ Classification automatique : Service, Endpoint, Maintenance, Surveillance
* ✅ IHM responsive (Flask + Bootstrap + DataTables)
* ✅ Cartographie graphique avec Vis.js
* ✅ Icônes personnalisées pour représenter les équipements

---

## 🔧 Types de scan

| Type de Scan | Informations collectées                                           | Fichier de sortie          |
| ------------ | ----------------------------------------------------------------- | -------------------------- |
| `quick`      | IP, nom NetBIOS, nom DNS                                          | `resultatrapide.json`      |
| `standard`   | IP, OS, ports TCP, rôle, nom DNS                                  | `resultatmoyen.json`       |
| `deep`       | IP, OS, ports, rôle, services + versions, vulnérabilités, nom DNS | `resultatapprofondie.json` |

---

## 📋 Structure du projet

```
.
├── app.py                    # Serveur Flask
├── scan.py                   # Script de scan et d'analyse
├── lastscan.txt              # Fichier de mémoire du dernier scan
├── resultatrapide.json       # Résultats du scan rapide
├── resultatmoyen.json        # Résultats du scan standard
├── resultatapprofondie.json  # Résultats du scan approfondi
├── results.json              # Exemple de sortie
├── requirements.txt          # Modules Python requis
|
├── static/
│   └── icons/                # Icônes d’équipements
│       ├── camera.png
│       ├── laptop.png
│       ├── printer.png
│       └── server.png
|
├── templates/
│   ├── index.html            # Page principale de l’IHM avec la cartographie
│   └── map.html              # Version isolée de la cartographie (optionnelle)
```

---

## 🚧 Prérequis

* Python 3.10+
* Nmap installé (ex: `sudo apt install nmap`)
* Accès `sudo` requis pour certains scans

---

## 🚀 Installation & Lancement

```bash
# Initialisation
python3 -m venv venv-sonde
source venv-sonde/bin/activate
pip install -r requirements.txt

# Lancer un scan manuellement
sudo venv-sonde/bin/python3 scan.py standard 192.168.1.0/24

# Démarrer le serveur Flask
venv-sonde/bin/python3 app.py
```

### Accès IHM

Accéder à : `http://<ip_de_la_sonde>:5000`

---

## 📊 Interface Web

* Visualisation des hôtes sous forme de tableau filtrable / triable
* Lancement de scan via formulaire (type + cible)
* Cartographie graphique dynamique
* Icônes personnalisées : laptop, serveur, imprimante, caméra, etc.

---

## 🌎 Cartographie dynamique (Vis.js)

Chaque machine apparaît connectée à la "Sonde" au centre :

* Couleur & icône selon le rôle
* Labels incluant IP + type de machine

---

## 🌐 Avenir / TODO

* [ ] Export PDF / CSV des résultats
* [ ] Historique des scans en base de données
* [ ] Alerting sur services critiques
* [ ] Ajout de graphiques d'évolution

---

## 🌐 Créateur

Ce projet a été conçu et développé par **Gaétan Guiraudie** dans le cadre de sa formation en sécurité des systèmes d'information.
