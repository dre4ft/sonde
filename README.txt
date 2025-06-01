🚀 Sonde d’Audit Réseau
=======================

Ce projet propose une sonde réseau légère, déployable sur un Raspberry Pi,
permettant de scanner un réseau local, identifier les machines, les classifier 
par rôle, et visualiser les résultats via une interface web intuitive.

---

🌟 Fonctionnalités principales
------------------------------
✅ Scan rapide, standard ou approfondi avec Nmap  
✅ Classification automatique : Service, Endpoint, Maintenance, Surveillance  
✅ IHM responsive (Flask + Bootstrap + DataTables)  
✅ Cartographie graphique avec Vis.js  
✅ Icônes personnalisées pour représenter les équipements  

---

🔧 Types de scan
----------------
| Type      | Informations collectées                                       | Fichier de sortie           |
|-----------|---------------------------------------------------------------|-----------------------------|
| quick     | IP, nom NetBIOS, nom DNS                                      | resultatrapide.json         |
| standard  | IP, OS, ports TCP, rôle, nom DNS                              | resultatmoyen.json          |
| deep      | IP, OS, ports, rôle, services + versions, vulnérabilités, DNS | resultatapprofondie.json    |

💡 Remarque : le *scan rapide* ne permet pas d’identifier le rôle d’un équipement.  
Aucune icône spécifique ne s’affichera dans la cartographie pour ces hôtes.

---

📋 Structure du projet
----------------------
.
├── app.py                    → Serveur Flask
├── scan.py                   → Script de scan et d’analyse
├── lastscan.txt              → Mémo du dernier scan
├── resultatrapide.json       → Résultat du scan rapide
├── resultatmoyen.json        → Résultat du scan standard
├── resultatapprofondie.json  → Résultat du scan approfondi
├── results.json              → Exemple de résultat
├── requirements.txt          → Modules Python requis

├── static/
│   └── icons/
│       ├── camera.png        → Icône caméra (Surveillance)
│       ├── laptop.png        → Icône laptop (Endpoint)
│       ├── printer.png       → Icône imprimante (Maintenance)
│       ├── server.png        → Icône serveur (Service)
│       └── unknown.png       → Icône générique si type non identifié

├── templates/
│   ├── index.html            → Interface principale avec formulaire et cartographie
│   └── map.html              → Version isolée de la cartographie

---

🚧 Prérequis
------------
- Python 3.10 ou +
- Nmap (sudo apt install nmap)
- Droits sudo pour les scans

---

🚀 Installation & Lancement
---------------------------
# Initialisation
python3 -m venv venv-sonde
source venv-sonde/bin/activate
pip install -r requirements.txt

# Scan manuel
sudo venv-sonde/bin/python3 scan.py standard 192.168.1.0/24

# Lancement du serveur Flask
venv-sonde/bin/python3 app.py

Puis ouvrir dans un navigateur :
http://<ip_du_raspberry>:5000

---

📊 Interface Web
----------------
- Tableau filtrable & triable
- Lancement de scans via IHM
- Cartographie dynamique
- Légende avec icônes : laptop, serveur, imprimante, caméra, etc.

---

🌎 Cartographie dynamique (Vis.js)
----------------------------------
- Chaque hôte relié à la sonde
- Icône selon le rôle détecté
- Label = IP de l’hôte
- Rôle inconnu ⇒ icône générique ou non affichée

📎 Astuce : ajouter une icône générique manuellement
cp static/icons/laptop.png static/icons/unknown.png

---

📈 Améliorations prévues
------------------------
- [ ] Export PDF / CSV
- [ ] Historique avec base de données
- [ ] Détection de services critiques
- [ ] Graphiques d’évolution
- [ ] Intégration passive avec Zeek (en cours)
