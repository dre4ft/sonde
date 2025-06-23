#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────────────
# BD/db.py  – stockage SQLite des scans + cache CVE local (sans dépendance réseau)
# ──────────────────────────────────────────────────────────────────────────────
import os
import json
import sqlite3
from datetime import datetime
from typing import List, Dict

from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime,
    Text, Float, ForeignKey
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "scans.db")

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    echo=False,
    connect_args={"check_same_thread": False},
)
Session = sessionmaker(bind=engine)
Base    = declarative_base()

# ─── Modèles
class Scan(Base):
    __tablename__ = "scans"
    id        = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    scan_type = Column(String)
    ip        = Column(String)
    os        = Column(String)
    hostname  = Column(String)
    netbios   = Column(String)
    ports     = Column(String)
    role      = Column(String)
    services  = Column(Text)
    cves      = Column(Text)

    services_rel = relationship(
        "Service", back_populates="scan",
        cascade="all, delete-orphan",
    )


class Service(Base):
    __tablename__ = "services"
    id      = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)

    port    = Column(Integer)
    name    = Column(String)
    product = Column(String)
    version = Column(String)
    cves    = Column(String)

    scan      = relationship("Scan", back_populates="services_rel")
    cve_assoc = relationship(
        "ServiceCVE", back_populates="service",
        cascade="all, delete-orphan",
    )


class CVE(Base):
    __tablename__ = "cves"
    id          = Column(Integer, primary_key=True)
    code        = Column(String, unique=True, index=True, nullable=False)
    cvss_score  = Column(Float)
    description = Column(Text)

    service_assoc = relationship(
        "ServiceCVE", back_populates="cve",
        cascade="all, delete-orphan",
    )


class ServiceCVE(Base):
    __tablename__ = "service_cves"
    service_id = Column(Integer, ForeignKey("services.id"), primary_key=True)
    cve_id     = Column(Integer, ForeignKey("cves.id"),    primary_key=True)

    service = relationship("Service", back_populates="cve_assoc")
    cve     = relationship("CVE",     back_populates="service_assoc")

# ─── Migration douce de l’ancien champ unique « scans »
_EXPECTED = {
    "id", "timestamp", "scan_type", "ip", "os", "hostname",
    "netbios", "ports", "role", "services", "cves",
}


def _automigrate() -> None:
    Base.metadata.create_all(engine)
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(scans);")
        present = {row[1] for row in cur.fetchall()}
        for col in _EXPECTED - present:
            cur.execute(f"ALTER TABLE scans ADD COLUMN {col} TEXT;")
        conn.commit()


def init_db() -> None:
    Base.metadata.create_all(engine)
    _automigrate()

# ─── Enregistrement
def save_scan_entry(scan_type: str, hosts: List[Dict]) -> None:
    session = Session()

    for host in hosts:
        host_cves = {
            cve for svc in host.get("services", []) for cve in svc.get("cves", [])
        }

        scan = Scan(
            timestamp=datetime.utcnow(),
            scan_type=scan_type,
            ip=host["ip"],
            os=host.get("os", ""),
            hostname=host.get("hostname", ""),
            netbios=host.get("netbios", ""),
            ports=",".join(map(str, host.get("ports", []))),
            role=host.get("role", ""),
            services=json.dumps(host.get("services", []), ensure_ascii=False),
            cves=",".join(sorted(host_cves)),
        )
        session.add(scan)
        session.flush()

        for svc_data in host.get("services", []):
            svc = Service(
                scan_id=scan.id,
                port=svc_data.get("port"),
                name=svc_data.get("name", ""),
                product=svc_data.get("product", ""),
                version=svc_data.get("version", ""),
                cves=",".join(svc_data.get("cves", [])),
            )
            session.add(svc)
            session.flush()

            for code in svc_data.get("cves", []):
                cve = session.query(CVE).filter_by(code=code).first()
                if not cve:
                    cve = CVE(code=code)
                    session.add(cve)
                    session.flush()
                session.add(ServiceCVE(service_id=svc.id, cve_id=cve.id))

    session.commit()
    session.close()