# BD/db.py

import os
import json
import sqlite3
from datetime import datetime

import vulners
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime,
    Text, Float, ForeignKey
)
from sqlalchemy.orm import (
    declarative_base, sessionmaker, relationship
)

# ─── CHEMIN BASE DE DONNÉES ────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "scans.db")

engine  = create_engine(
    f"sqlite:///{DB_PATH}",
    echo=False,
    connect_args={"check_same_thread": False}
)
Session = sessionmaker(bind=engine)
Base    = declarative_base()

# ─── MODÈLES ───────────────────────────────────────────────────────────────────

class Scan(Base):
    __tablename__ = "scans"

    id         = Column(Integer, primary_key=True)
    timestamp  = Column(DateTime, default=datetime.utcnow, nullable=False)
    scan_type  = Column(String)
    ip         = Column(String)
    os         = Column(String)
    hostname   = Column(String)
    netbios    = Column(String)
    ports      = Column(String)
    role       = Column(String)
    services   = Column(Text)  # JSON brut pour rétrocompatibilité
    cves       = Column(Text)  # CSV brut pour rétrocompatibilité

    services_rel = relationship(
        "Service",
        back_populates="scan",
        cascade="all, delete-orphan"
    )

class Service(Base):
    __tablename__ = "services"

    id       = Column(Integer, primary_key=True)
    scan_id  = Column(Integer, ForeignKey("scans.id"), nullable=False)

    port     = Column(Integer)
    name     = Column(String)
    product  = Column(String)
    version  = Column(String)
    cves     = Column(String)  # CSV

    scan     = relationship("Scan", back_populates="services_rel")
    cve_assoc = relationship(
        "ServiceCVE",
        back_populates="service",
        cascade="all, delete-orphan"
    )

class CVE(Base):
    __tablename__ = "cves"

    id          = Column(Integer, primary_key=True)
    code        = Column(String, unique=True, index=True, nullable=False)
    cvss_score  = Column(Float)
    description = Column(Text)

    service_assoc = relationship(
        "ServiceCVE",
        back_populates="cve",
        cascade="all, delete-orphan"
    )

class ServiceCVE(Base):
    __tablename__ = "service_cves"

    service_id = Column(Integer, ForeignKey("services.id"), primary_key=True)
    cve_id     = Column(Integer, ForeignKey("cves.id"), primary_key=True)

    service    = relationship("Service", back_populates="cve_assoc")
    cve        = relationship("CVE", back_populates="service_assoc")

# ─── AUTOMIGRATE POUR RÉTROCOMPATIBILITÉ ─────────────────────────────────────

_EXPECTED_COLUMNS = {
    "id", "timestamp", "scan_type", "ip", "os", "hostname",
    "netbios", "ports", "role", "services", "cves",
}

def _automigrate():
    Base.metadata.create_all(engine)
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(scans);")
        present = {row[1] for row in cur.fetchall()}
        missing = _EXPECTED_COLUMNS - present
        for col in missing:
            cur.execute(f"ALTER TABLE scans ADD COLUMN {col} TEXT;")
        if missing:
            conn.commit()

def init_db():
    Base.metadata.create_all(engine)
    _automigrate()

# ─── FONCTION D’ENREGISTREMENT DE SCAN + CACHE CVE ────────────────────────────

def save_scan_entry(scan_type: str, host_data: list[dict]) -> None:
    """
    Enregistre un Scan par hôte, et met en cache les CVEs via l’API Vulners.
    """
    session = Session()

    # Initialisation Vulners API
    api_key = os.environ.get("VULNERS_API_KEY", "")
    vuln_api = vulners.Vulners(api_key) if api_key else None

    # Pour chaque hôte du scan, créer une entrée Scan indépendante
    for host in host_data:
        # Concatène les CVEs de ce host
        host_cves = []
        for svc in host.get("services", []):
            host_cves.extend(svc.get("cves", []))

        scan = Scan(
            timestamp = datetime.utcnow(),
            scan_type = scan_type,
            ip        = host.get("ip"),
            os        = host.get("os", ""),
            hostname  = host.get("hostname", ""),
            netbios   = host.get("netbios", ""),
            ports     = ",".join(str(p) for p in host.get("ports", [])),
            role      = host.get("role", ""),
            services  = json.dumps(host.get("services", []), ensure_ascii=False),
            cves      = ",".join(host_cves)
        )
        session.add(scan)
        session.flush()  # pour obtenir scan.id

        # Enregistrer chaque service lié à ce host
        for svc_data in host.get("services", []):
            svc = Service(
                scan_id = scan.id,
                port    = svc_data.get("port"),
                name    = svc_data.get("name", ""),
                product = svc_data.get("product", ""),
                version = svc_data.get("version", ""),
                cves    = ",".join(svc_data.get("cves", []))
            )
            session.add(svc)
            session.flush()  # pour obtenir svc.id

            # Mettre en cache chaque CVE
            for cve_code in svc_data.get("cves", []):
                cve_code = cve_code.strip()
                if not cve_code:
                    continue

                # Si déjà en cache, on récupère
                cve = session.query(CVE).filter_by(code=cve_code).first()
                if not cve and vuln_api:
                    try:
                        details = vuln_api.cve(cve_code)
                        score   = float(details.get("cvss", 0))
                        desc    = details.get("description", "")
                    except Exception:
                        score, desc = None, None

                    cve = CVE(
                        code        = cve_code,
                        cvss_score  = score,
                        description = desc
                    )
                    session.add(cve)
                    session.flush()

                # Association N–N
                if cve:
                    assoc = ServiceCVE(
                        service_id = svc.id,
                        cve_id     = cve.id
                    )
                    session.add(assoc)

    session.commit()
    session.close()
