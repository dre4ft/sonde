# Sonde d'Audit Réseau

## Présentation

Ce projet est une application web (IHM) d'audit réseau, développée en Python avec Flask. L'utilisateur interagit uniquement via l'interface web, qui pilote en arrière-plan les scripts de scan et d'analyse. Les scripts (`scan_ia.py`, `scan.py`, etc.) ne sont pas destinés à être lancés directement par l'utilisateur, mais sont appelés par l'application web (`app.py`).

## Fonctionnement

- L'utilisateur accède à l'interface web (Flask) pour lancer des scans, visualiser les résultats, l'historique, la cartographie, etc.
- L'IHM permet de choisir le type de scan, la plage IP, et d'autres options.
- L'application web orchestre les scripts de scan, collecte les résultats, les enrichit (rôles, vulnérabilités), et les stocke en base de données (SQLite).
- Les résultats sont affichés dans l'interface web, avec des fonctionnalités de recherche, de cartographie, et d'export.

## Structure du projet

- `app.py` : Point d'entrée principal, serveur Flask, routes web, logique d'orchestration
- `scan_ia.py`, `scan.py`, `scan_passif.py`, `scanV2.py` : Scripts de scan réseau, appelés par `app.py` (jamais directement par l'utilisateur)
- `ai_local.py` : Classification locale des rôles d'équipements
- `BD/scan_db.py`, `BD/packet_db.py` : Gestion des bases SQLite
- `templates/` : Templates HTML (Jinja2) pour l'IHM
- `static/` : Fichiers statiques (icônes, CSS, JS)
- `requirements.txt` : Dépendances Python
- `rules.json` : Règles de catégorisation

## Installation

### Prérequis
- Python 3.8+
- Nmap installé (`sudo apt install nmap` ou `brew install nmap`)
- MongoDB (optionnel, pour la base CVE locale)

### Dépendances Python
```sh
pip install -r requirements.txt
```

### Clé API Vulners (optionnel)
Pour activer la détection de vulnérabilités en ligne :
```sh
export VULNERS_API_KEY="votre_clé_api"
```
Ajoutez-la à votre shell (~/.zshrc, ~/.bashrc).


## Utilisation

1. Lancez l'application web :
```sh
python3 app.py
```
2. Ouvrez votre navigateur sur http://localhost:5000
3. Utilisez l'IHM pour lancer des scans, consulter les résultats, l'historique, la cartographie, etc.

**Remarque :**
- Les scripts de scan ne doivent pas être lancés manuellement. Toute l'interaction se fait via l'interface web.
- Les résultats sont stockés en base SQLite et accessibles via l'IHM.

## Stockage des résultats
- Fichiers JSON (générés automatiquement)
- Base SQLite : historique des scans et services
- MongoDB : base locale des CVEs (optionnel)

## Sécurité
- Clé secrète Flask définie dans `app.py`
- Clé Vulners dans l'environnement (jamais dans le code)
- Encodage JSON UTF-8, gestion des erreurs

## Évolutions possibles
- Filtres par niveau de sévérité CVE
- Authentification admin
- Export CSV/PDF
- Analyse passive avancée
- Détection de comportements anormaux

## Auteurs
Projet open source, contributions bienvenues !

