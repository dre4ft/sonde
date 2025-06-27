#!/usr/bin/env python3
"""
ai_local.py - Classification hybride multi-méthodes pour la sonde réseau
Combine patterns, services, ports et zero-shot pour une classification robuste
"""
from transformers import pipeline
import json
import re
from typing import Dict, List, Tuple, Any
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Chargement des patterns
try:
    with open("device_patterns.json", "r", encoding="utf-8") as f:
        DEVICE_PATTERNS = json.load(f)
except FileNotFoundError:
    logger.warning("device_patterns.json non trouvé, utilisation patterns par défaut")
    DEVICE_PATTERNS = {}

# Pipeline zero-shot
classifier = pipeline(
    "zero-shot-classification",
    model="valhalla/distilbart-mnli-12-1",
    device=-1,
    hypothesis_template="Cet appareil est un(e) {}."
)

# Labels avec descriptions enrichies pour améliorer zero-shot
ROLE_LABELS = {
    "Endpoint": "ordinateur personnel, PC, laptop, poste de travail",
    "Smartphone": "téléphone mobile, smartphone, tablette",
    "Service": "serveur, routeur, switch, équipement réseau",
    "Maintenance": "imprimante, scanner, équipement de maintenance",
    "Surveillance": "caméra de surveillance, système de sécurité",
    "IoT": "objet connecté, capteur, thermostat intelligent",
    "Database": "serveur de base de données",
    "Web service": "serveur web, application web",
    "Remote access": "serveur d'accès distant, VPN",
    "Mail service": "serveur de messagerie",
    "DNS": "serveur DNS",
    "Autre": "équipement non identifié"
}

# Mapping services/ports vers rôles avec scores de confiance
SERVICE_ROLE_MAP = {
    # Databases
    "mysql": ("Database", 0.9),
    "postgresql": ("Database", 0.9),
    "mongodb": ("Database", 0.9),
    "oracle": ("Database", 0.9),
    "mssql": ("Database", 0.9),
    
    # Web
    "http": ("Web service", 0.8),
    "https": ("Web service", 0.8),
    "nginx": ("Web service", 0.9),
    "apache": ("Web service", 0.9),
    
    # Remote access
    "ssh": ("Remote access", 0.8),
    "rdp": ("Remote access", 0.9),
    "vnc": ("Remote access", 0.9),
    "telnet": ("Remote access", 0.7),
    
    # Mail
    "smtp": ("Mail service", 0.9),
    "pop3": ("Mail service", 0.9),
    "imap": ("Mail service", 0.9),
    
    # Network services
    "dns": ("DNS", 0.95),
    "dhcp": ("Service", 0.8),
    
    # Surveillance
    "rtsp": ("Surveillance", 0.9),
    "onvif": ("Surveillance", 0.95),
    
    # Printing
    "ipp": ("Maintenance", 0.9),
    "jetdirect": ("Maintenance", 0.9),
    
    # IoT
    "mqtt": ("IoT", 0.85),
    "coap": ("IoT", 0.85),
    "snmp": ("IoT", 0.7),
}

PORT_ROLE_MAP = {
    # Databases
    3306: ("Database", 0.8),      # MySQL
    5432: ("Database", 0.8),      # PostgreSQL
    27017: ("Database", 0.8),     # MongoDB
    1521: ("Database", 0.8),      # Oracle
    1433: ("Database", 0.8),      # SQL Server
    
    # Web
    80: ("Web service", 0.7),
    443: ("Web service", 0.7),
    8080: ("Web service", 0.7),
    8443: ("Web service", 0.7),
    
    # Remote
    22: ("Remote access", 0.7),
    3389: ("Remote access", 0.9),
    5900: ("Remote access", 0.8),
    
    # Mail
    25: ("Mail service", 0.8),
    110: ("Mail service", 0.8),
    143: ("Mail service", 0.8),
    587: ("Mail service", 0.8),
    993: ("Mail service", 0.8),
    995: ("Mail service", 0.8),
    
    # Network
    53: ("DNS", 0.9),
    67: ("Service", 0.7),
    68: ("Service", 0.7),
    
    # Surveillance
    554: ("Surveillance", 0.9),
    8554: ("Surveillance", 0.8),
    
    # Printing
    9100: ("Maintenance", 0.9),
    631: ("Maintenance", 0.8),
    
    # IoT
    1883: ("IoT", 0.8),
    8883: ("IoT", 0.8),
    5683: ("IoT", 0.8),
    161: ("IoT", 0.6),
}

class HybridClassifier:
    def __init__(self):
        self.weights = {
            "pattern": 0.35,      # Patterns explicites
            "service": 0.30,      # Services détectés
            "port": 0.15,         # Ports ouverts
            "zero_shot": 0.15,    # IA zero-shot
            "os": 0.05            # OS détecté
        }
    
    def extract_info(self, host_str: str) -> Dict[str, Any]:
        """Extrait les informations structurées du string host"""
        info = {
            "ip": "",
            "hostname": "",
            "os": "",
            "oui": "",
            "ttl": "",
            "ports": [],
            "services": []
        }
        
        # Extraction par regex
        patterns = {
            "ip": r"IP=([^,\s]+)",
            "hostname": r"hostname=([^,\s]+)",
            "os": r"OS=([^,]+?)(?=,\s*(?:OUI|TTL|ports|services|$))",
            "oui": r"OUI=([^,\s]+)",
            "ttl": r"TTL=([^,\s]+)",
            "ports": r"ports=\[([^\]]*)\]",
            "services": r"services=\[([^\]]*)\]"
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, host_str, re.IGNORECASE)
            if match:
                if key in ["ports", "services"]:
                    # Parse les listes
                    content = match.group(1)
                    if content:
                        items = [item.strip().strip("'\"") for item in content.split(",")]
                        info[key] = [item for item in items if item]
                else:
                    info[key] = match.group(1).strip()
        
        return info
    
    def extract_from_dict(self, host_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Extrait les informations depuis un dictionnaire (pour intégration scan.py)"""
        info = {
            "ip": host_dict.get("ip", ""),
            "hostname": host_dict.get("hostname", ""),
            "os": host_dict.get("os", "Unknown"),
            "oui": "",  # À extraire via scapy/nmap si besoin
            "ttl": "",  # Idem
            "ports": [str(p) for p in host_dict.get("ports", [])],
            "services": []
        }
        
        # Extraction des noms de services
        for svc in host_dict.get("services", []):
            if isinstance(svc, dict):
                name = svc.get("name", "")
                product = svc.get("product", "")
                service_str = f"{name}/{product}" if product else name
                if service_str:
                    info["services"].append(service_str)
        
        return info
    
    def classify_by_pattern(self, info: Dict[str, Any]) -> Tuple[str, float]:
        """Classification par patterns dans hostname/OUI"""
        hostname = info.get("hostname", "").lower()
        oui = info.get("oui", "").lower()
        
        best_match = ("Autre", 0.0)
        
        for pattern, pattern_info in DEVICE_PATTERNS.items():
            pattern_lower = pattern.lower()
            score = 0.0
            
            # Check hostname
            if pattern_lower in hostname:
                score = 0.9
            # Check OUI (constructeur)
            elif pattern_lower in oui:
                score = 0.7
            
            if score > best_match[1]:
                role = pattern_info.get("role", pattern_info.get("label", "Autre"))
                best_match = (role, score)
        
        return best_match
    
    def classify_by_services(self, info: Dict[str, Any]) -> Tuple[str, float]:
        """Classification basée sur les services détectés"""
        services = info.get("services", [])
        if not services:
            return ("Autre", 0.0)
        
        role_scores = {}
        for service in services:
            service_lower = service.lower()
            for svc_pattern, (role, confidence) in SERVICE_ROLE_MAP.items():
                if svc_pattern in service_lower:
                    if role not in role_scores:
                        role_scores[role] = []
                    role_scores[role].append(confidence)
        
        if not role_scores:
            return ("Autre", 0.0)
        
        # Moyenne des scores pour chaque rôle
        best_role = max(role_scores.items(), 
                       key=lambda x: sum(x[1]) / len(x[1]))
        return (best_role[0], sum(best_role[1]) / len(best_role[1]))
    
    def classify_by_ports(self, info: Dict[str, Any]) -> Tuple[str, float]:
        """Classification basée sur les ports ouverts"""
        ports_str = info.get("ports", [])
        if not ports_str:
            return ("Autre", 0.0)
        
        # Conversion en int
        ports = []
        for p in ports_str:
            try:
                ports.append(int(p))
            except ValueError:
                continue
        
        if not ports:
            return ("Autre", 0.0)
        
        role_scores = {}
        for port in ports:
            if port in PORT_ROLE_MAP:
                role, confidence = PORT_ROLE_MAP[port]
                if role not in role_scores:
                    role_scores[role] = []
                role_scores[role].append(confidence)
        
        if not role_scores:
            # Heuristique : beaucoup de ports = serveur
            if len(ports) > 5:
                return ("Service", 0.6)
            return ("Endpoint", 0.4)
        
        best_role = max(role_scores.items(), 
                       key=lambda x: sum(x[1]) / len(x[1]))
        return (best_role[0], sum(best_role[1]) / len(best_role[1]))
    
    def classify_by_os(self, info: Dict[str, Any]) -> Tuple[str, float]:
        """Classification basée sur l'OS détecté"""
        os_str = info.get("os", "").lower()
        
        if "camera" in os_str or "dvr" in os_str:
            return ("Surveillance", 0.9)
        elif "printer" in os_str:
            return ("Maintenance", 0.9)
        elif "android" in os_str or "ios" in os_str:
            return ("Smartphone", 0.9)
        elif "windows" in os_str:
            # Windows Server vs Desktop
            if "server" in os_str:
                return ("Service", 0.8)
            return ("Endpoint", 0.7)
        elif "linux" in os_str:
            # Linux peut être serveur ou endpoint
            ports = info.get("ports", [])
            if len(ports) > 3:
                return ("Service", 0.6)
            return ("Endpoint", 0.5)
        
        return ("Autre", 0.0)
    
    def classify_zero_shot(self, host_str: str, info: Dict[str, Any]) -> Tuple[str, float]:
        """Classification zero-shot avec contexte enrichi"""
        # Construction d'une description enrichie
        description_parts = [f"Appareil réseau avec IP {info['ip']}"]
        
        if info.get("hostname"):
            description_parts.append(f"nom '{info['hostname']}'")
        if info.get("os") and info["os"] != "Unknown":
            description_parts.append(f"système '{info['os']}'")
        if info.get("services"):
            description_parts.append(f"services {', '.join(info['services'][:3])}")
        if info.get("ports"):
            description_parts.append(f"ports {', '.join(info['ports'][:5])}")
        
        description = ", ".join(description_parts)
        
        try:
            result = classifier(
                sequences=description,
                candidate_labels=list(ROLE_LABELS.keys()),
                multi_label=False
            )
            
            best_label = result["labels"][0]
            score = result["scores"][0]
            
            return (best_label, score)
        except Exception as e:
            logger.error(f"Erreur zero-shot: {e}")
            return ("Autre", 0.0)
    
    def classify(self, host_str: str) -> Dict[str, Any]:
        """Classification hybride combinant toutes les méthodes"""
        # Skip les exemples du few-shot
        if host_str.startswith("Exemples:") or host_str.startswith("Maintenant"):
            return None
        
        info = self.extract_info(host_str)
        
        # Application de chaque méthode
        results = {
            "pattern": self.classify_by_pattern(info),
            "service": self.classify_by_services(info),
            "port": self.classify_by_ports(info),
            "os": self.classify_by_os(info),
            "zero_shot": self.classify_zero_shot(host_str, info)
        }
        
        # Calcul du score pondéré pour chaque rôle
        role_scores = {}
        for method, (role, score) in results.items():
            if role != "Autre" or score > 0:
                weight = self.weights[method]
                if role not in role_scores:
                    role_scores[role] = 0
                role_scores[role] += score * weight
        
        # Sélection du meilleur rôle
        if not role_scores:
            best_role = "Endpoint"
            best_score = 0.3
        else:
            best_role = max(role_scores.items(), key=lambda x: x[1])
            best_role, best_score = best_role[0], best_role[1]
        
        # Mapping label/role pour compatibilité
        label_mapping = {
            "Database": "Service",
            "Web service": "Service", 
            "Remote access": "Service",
            "Mail service": "Service",
            "DNS": "Service"
        }
        
        broad_role = label_mapping.get(best_role, best_role)
        
        return {
            "host": host_str,
            "label": best_role,        # Type spécifique
            "role": broad_role,        # Catégorie large
            "score": min(best_score, 1.0),
            "details": results,        # Détails pour debug
            "info": info              # Infos extraites
        }
    
    def classify_dict(self, host_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Classification depuis un dictionnaire (pour scan.py)"""
        info = self.extract_from_dict(host_dict)
        
        # Application de chaque méthode
        results = {
            "pattern": self.classify_by_pattern(info),
            "service": self.classify_by_services(info),
            "port": self.classify_by_ports(info),
            "os": self.classify_by_os(info),
            "zero_shot": ("Autre", 0.0)  # Skip zero-shot pour les dicts
        }
        
        # Calcul du score pondéré
        role_scores = {}
        for method, (role, score) in results.items():
            if role != "Autre" or score > 0:
                weight = self.weights[method]
                if role not in role_scores:
                    role_scores[role] = 0
                role_scores[role] += score * weight
        
        # Sélection du meilleur rôle
        if not role_scores:
            best_role = "Endpoint"
            best_score = 0.3
        else:
            best_role = max(role_scores.items(), key=lambda x: x[1])
            best_role, best_score = best_role[0], best_role[1]
        
        # Mapping
        label_mapping = {
            "Database": "Service",
            "Web service": "Service", 
            "Remote access": "Service",
            "Mail service": "Service",
            "DNS": "Service"
        }
        
        broad_role = label_mapping.get(best_role, best_role)
        
        return {
            "label": best_role,        # Type spécifique
            "role": broad_role,        # Catégorie large
            "score": min(best_score, 1.0),
            "ai_method": "hybrid"      # Pour tracer la méthode utilisée
        }

# Instance globale
hybrid_classifier = HybridClassifier()

def classify_roles_local(hosts: List[str]) -> List[Dict[str, Any]]:
    """Fonction principale de classification compatible avec l'existant"""
    results = []
    
    for host in hosts:
        classification = hybrid_classifier.classify(host)
        if classification:  # Skip les None (exemples few-shot)
            results.append(classification)
    
    return results


def classify_scan_results(scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Classification directe des résultats de scan (pour intégration dans scan.py)"""
    for result in scan_results:
        classification = hybrid_classifier.classify_dict(result)
        # Mise à jour du résultat avec la classification
        result["device_type"] = classification["label"]
        result["type"] = classification["label"]
        result["role"] = classification["role"]
        result["ai_score"] = classification["score"]
        result["ai_method"] = classification["ai_method"]
    
    return scan_results


if __name__ == "__main__":
    # Tests
    test_hosts = [
        "IP=192.168.1.1, hostname=livebox.home, OS=Linux, OUI=00:1A:2B, TTL=64, ports=[53,80,443], services=[dns,http,https]",
        "IP=192.168.1.19, hostname=xiaomi-13t-pro.home, OS=Unknown, OUI=AA:BB:CC, TTL=128, ports=[], services=[]",
        "IP=192.168.1.100, hostname=srv-db01, OS=Ubuntu Linux, ports=[3306,22], services=[mysql,ssh]",
        "IP=192.168.1.50, hostname=HP-LaserJet, OS=Printer, ports=[9100,80], services=[jetdirect,http]",
        "IP=192.168.1.75, hostname=cam-entrance, OS=Linux embedded, ports=[554,80], services=[rtsp,http]"
    ]
    
    results = classify_roles_local(test_hosts)
    for r in results:
        print(f"\n{r['host']}")
        print(f"  → Type: {r['label']} (score: {r['score']:.2f})")
        print(f"  → Rôle: {r['role']}")
        if 'details' in r:
            print(f"  → Détails: {r['details']}")