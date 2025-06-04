# BD/db.py

import os
import json
import sqlite3
from datetime import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Text, ForeignKey
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "scans.db")

engine  = create_engine(f"sqlite:///{DB_PATH}", echo=False)
Session = sessionmaker(bind=engine)
Base    = declarative_base()

class Scan(Base):
    __tablename__ = "scans"

    id        = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    scan_type = Column(String)
    ip        = Column(String)
    os        = Column(String)
    hostname  = Column(String)
    netbios   = Column(String)
    ports     = Column(String)
    role      = Column(String)

    # Ancienne colonne « services » (texte) – on la garde si besoin de rétrocompatibilité
    services  = Column(Text)
    # Ancienne colonne « cves » (texte) – idem
    cves      = Column(Text)

    # Relation vers la nouvelle table Service
    services_rel = relationship(
        "Service",
        back_populates="scan",
        cascade="all, delete-orphan"
    )

class Service(Base):
    __tablename__ = "services"

    id      = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)

    port    = Column(Integer)   # ex. 80, 443, 22, etc.
    name    = Column(String)    # ex. "http", "ssh", etc.
    product = Column(String)    # ex. "nginx", "OpenSSH", …
    version = Column(String)    # ex. "1.18", "9.2p1 Debian 2+deb12u6", …
    cves    = Column(String)    # CSV de CVEs, p. ex. "CVE-2021-1234,CVE-2022-5678"

    scan = relationship("Scan", back_populates="services_rel")


_EXPECTED_COLUMNS = {
    "id", "timestamp", "scan_type", "ip", "os", "hostname",
    "netbios", "ports", "role", "services", "cves",
}

def _automigrate():
    """
    - Crée la table 'scans' et 'services' si elles n’existent pas (via create_all).
    - Vérifie ensuite sur 'scans' s’il manque des colonnes (ex. 'cves'), et
      si oui, fait ALTER TABLE pour les ajouter.
    """
    # 1) Assure la création des tables 'scans' et 'services'
    Base.metadata.create_all(engine)

    # 2) Vérifier la table 'scans' et ajouter les colonnes manquantes
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(scans);")
        present = {row[1] for row in cur.fetchall()}  # row[1] = nom de colonne
        missing = _EXPECTED_COLUMNS - present
        for col in missing:
            cur.execute(f"ALTER TABLE scans ADD COLUMN {col} TEXT;")
        if missing:
            conn.commit()

def init_db():
    """
    - Crée toutes les tables si besoin
    - Lance la mini-migration pour 'scans' (ajout de colonnes manquantes)
    """
    Base.metadata.create_all(engine)
    _automigrate()


def save_scan_entry(scan_type: str, host_data: list[dict]) -> None:
    session = Session()

    for host in host_data:
        ports_txt     = ",".join(map(str, host.get("ports", [])))
        services_list = host.get("services", [])   # peut être liste de dicts ou liste de chaînes
        cves_list     = host.get("cves", [])

        # On remplit la colonne “services” brute (texte) à l’ancienne
        if services_list and isinstance(services_list[0], dict):
            services_txt = json.dumps(services_list, ensure_ascii=False)
        else:
            services_txt = "\n".join(services_list)

        cves_txt = ",".join(cves_list)

        scan_entry = Scan(
            scan_type = scan_type,
            ip        = host.get("ip"),
            os        = host.get("os", ""),
            hostname  = host.get("hostname", ""),
            netbios   = host.get("netbios", ""),
            ports     = ports_txt,
            role      = host.get("role", ""),
            services  = services_txt,
            cves      = cves_txt
        )
        session.add(scan_entry)
        session.flush()

        # **NOUVEAU :** même si services_list est une simple chaîne (ex. "80/http"), on crée un Service
        if services_list:
            # S’il s’agit de dicts, on se comporte comme avant
            if isinstance(services_list[0], dict):
                for svc in services_list:
                    svc_port = svc.get("port")
                    svc_name = svc.get("name", "")
                    svc_prod = svc.get("product", "")
                    svc_vers = svc.get("version", "")
                    svc_cves = ",".join(svc.get("cves", []))
                    service_entry = Service(
                        scan_id = scan_entry.id,
                        port    = svc_port,
                        name    = svc_name,
                        product = svc_prod,
                        version = svc_vers,
                        cves    = svc_cves
                    )
                    session.add(service_entry)
            else:
                # Si c’est une simple chaîne “80/http” par exemple, on la parse manuellement
                for line in services_list:
                    # On peut faire “80/http” => port=80, name=”http” et rien d’autre
                    parts = line.split('/', 1)
                    try:
                        p_num = int(parts[0])
                    except ValueError:
                        p_num = None
                    p_name = parts[1] if len(parts) > 1 else ""
                    service_entry = Service(
                        scan_id = scan_entry.id,
                        port    = p_num,
                        name    = p_name,
                        product = "",    # pas d’info produit/version dans ce cas
                        version = "",
                        cves    = ""
                    )
                    session.add(service_entry)

    session.commit()
    session.close()
