 Configuration de la clé API VulnersAdd commentMore actions
Pour activer la détection de vulnérabilités (CVEs), vous devez définir la clé API de Vulners via une variable d’environnement nommée VULNERS_API_KEY.

Exemple (dans le terminal ou le fichier ~/.bashrc) :
bash
Copier
Modifier
export VULNERS_API_KEY="votre_clé_api"
Option recommandée (dans le venv) :
Ajoutez cette ligne à la fin du fichier venv-sonde/bin/activate :

bash
Copier
Modifier
export VULNERS_API_KEY="votre_clé_api"
Cela garantit que la clé est chargée automatiquement à chaque activation de l’environnement virtuel.


🧩 Fonctionnement de la sonde d’audit réseau
🎯 Objectif principal
La sonde a pour but d'analyser le réseau local afin de :

détecter les machines actives (par balayage IP),

identifier leurs rôles (poste utilisateur, serveur, caméra...),

recenser les ports/services exposés,

et relever les éventuelles vulnérabilités (CVEs) connues via la base Vulners.

Elle centralise ces informations dans une interface web claire, interactive et exploitable par un administrateur.

⚙️ Architecture générale
1. Composants principaux
Élément	Rôle
scan.py	Script principal qui réalise les scans (Nmap + enrichissements).
app.py	Application Flask qui gère l’interface web et les routes backend.
BD.db	Base SQLite avec SQLAlchemy stockant l’historique des scans.
index.html	Page principale de visualisation des résultats.
historique.html	Page dédiée à l’historique complet des scans enregistrés.

🔍 Processus de scan
Étape 1 : Lancement
Depuis l’IHM (index.html), l’utilisateur peut :

choisir un type de scan (rapide, standard, approfondi),

spécifier une plage IP (192.168.1.0/24),

activer ou non l’option -sV (detection des versions de services).

Cela déclenche la route /scan dans Flask (POST), qui exécute scan.py via un subprocess.

Étape 2 : Collecte et enrichissement
Le script scan.py effectue :

Un scan réseau avec Nmap, selon les options choisies.

Une tentative de catégorisation du rôle de chaque hôte (Endpoint, Service, Maintenance, etc.).

Une résolution des noms DNS/NetBIOS.

Une interrogation de l’API Vulners (si activée) pour identifier les CVE associées aux services détectés.

Les résultats sont :

enregistrés dans un fichier .json local (resultat*.json) pour consultation immédiate,

et insérés dans la base de données via SQLAlchemy (table Scan, Service).

Étape 3 : Affichage dynamique
🔹 Mode par défaut
Lors de l’accès à /, Flask lit le fichier du dernier scan effectué (lastscan.txt) et charge son contenu JSON dans la variable data.

🔹 Mode "historique"
L'utilisateur peut aussi choisir un scan passé dans une liste déroulante (dates), qui déclenche la route /show_scan?scan_time=....
Flask reconstruit alors data à partir des enregistrements SQL (Scan + Service) pour cette date.

Étape 4 : Rendu dans l’IHM
La page affiche :

un tableau dynamique avec les hôtes détectés, leur OS, leurs ports ouverts, leurs services et leurs vulnérabilités,

une carte réseau interactive (grâce à Vis.js),

des filtres et éléments visuels : icônes de rôles, badge de CVE, etc.

Les CVEs sont abrégées par défaut : seules les 5 premières s'affichent, avec un lien "Voir plus" pour révéler les suivantes (via Bootstrap Collapse).

📦 Stockage des résultats
1. Base de données (SQLite)
Table Scan : un enregistrement par machine scannée (avec horodatage, IP, OS...).

Table Service : services détectés liés à chaque Scan, avec leurs CVE associées.

2. Fichiers JSON
Utilisés pour afficher rapidement les résultats récents dans l’interface.

Fichiers typiques : resultatrapide.json, resultatmoyen.json, resultatapprofondie.json.

🛡️ Fonctionnalités de sécurité
Clé secrète Flask définie dans app.secret_key.

Protection API : la clé Vulners est injectée dans l’environnement, sans stockage direct dans le code.

Encodage JSON en UTF-8, gestion des erreurs de parsing.

Logs et messages d'erreur clairs via flash() pour aider au debug.

✅ Fonctionnalités principales en résumé
Fonction	Implémenté
Scan Nmap avec ou sans détection de version	✔️
Détection de rôles d’équipements	✔️
Résolution DNS / NetBIOS	✔️
Détection de CVEs via Vulners	✔️
Stockage base SQLite	✔️
Consultation JSON ou base selon contexte	✔️
Interface claire + responsive + carto	✔️
Historique de scans consultable	✔️
Réduction dynamique des longues listes CVE	✔️

🚀 Idées d’évolutions possibles
Affichage filtrable par niveau de sévérité CVE (critique, haut, moyen, bas).

Intégration d’une authentification admin.

Ajout d’un export PDF ou CSV.

Analyse passive complémentaire (via Zeek, par exemple).

Détection de comportements anormaux (à venir ?).