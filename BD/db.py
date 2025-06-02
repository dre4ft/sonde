# BD/db.py

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import os

# Chemin de la base
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scans.db")

engine = create_engine(f"sqlite:///{DB_PATH}", echo=False)
Session = sessionmaker(bind=engine)
Base = declarative_base()

# Modèle Scan
class Scan(Base):
    __tablename__ = 'scans'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    scan_type = Column(String)
    ip = Column(String)
    os = Column(String)
    hostname = Column(String)
    netbios = Column(String)
    ports = Column(String)
    role = Column(String)
    services = Column(Text)

# Init de la BDD
def init_db():
    Base.metadata.create_all(engine)

# Enregistrement
def save_scan_entry(scan_type, host_data):
    session = Session()
    for host in host_data:
        entry = Scan(
            scan_type=scan_type,
            ip=host.get("ip"),
            os=host.get("os", ""),
            hostname=host.get("hostname", ""),
            netbios=host.get("netbios", ""),
            ports=",".join(map(str, host.get("ports", []))),
            role=host.get("role", ""),
            services="\n".join(host.get("services", [])) if "services" in host else ""
        )
        session.add(entry)
    session.commit()
    session.close()
