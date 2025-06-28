import os
from datetime import datetime
from typing import List
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

# Configuration base de données
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "packets.db")

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False},
    echo=False,
)

SessionPackets = sessionmaker(bind=engine)
Base = declarative_base()

# Modèles ORM

class CaptureSession(Base):
    __tablename__ = "capture_sessions"
    id = Column(Integer, primary_key=True, index=True)
    start_time = Column(DateTime, default=datetime.utcnow)
    interface = Column(String, nullable=False)
    packets = relationship("Packet", back_populates="session", cascade="all, delete-orphan")


class Packet(Base):
    __tablename__ = "packets"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src_ip = Column(String)
    dst_ip = Column(String)
    protocol = Column(String)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    raw = Column(Text)
    rule_matched = Column(Boolean, default=False)
    session_id = Column(Integer, ForeignKey("capture_sessions.id"))

    session = relationship("CaptureSession", back_populates="packets")

    # Relation inverse vers KO_packet (0 ou 1)
    ko_packet = relationship("KO_packet", back_populates="packet", uselist=False)


class KO_packet(Base):
    __tablename__ = "ko_packets"
    id = Column(Integer, primary_key=True, index=True)

    # Référence vers Packet (1:1)
    packet_id = Column(Integer, ForeignKey("packets.id"), unique=True, nullable=False)

    rules = Column(Text, nullable=False)

    packet = relationship("Packet", back_populates="ko_packet")


# Initialisation de la base
def init_packet_db():
    Base.metadata.create_all(bind=engine)


# --- Fonctions CRUD ---

def add_ko_packet(packet: Packet, rules: str) -> KO_packet:
    session = SessionPackets()
    ko_pkt = KO_packet(
        packet=packet,
        rules=rules
    )
    session.add(ko_pkt)
    session.commit()
    session.refresh(ko_pkt)
    session.close()
    return ko_pkt


def get_ko_packets() -> List[KO_packet]:
    session = SessionPackets()
    ko_packets = session.query(KO_packet).all()
    session.close()
    return ko_packets


def create_capture_session(interface: str) -> CaptureSession:
    session = SessionPackets()
    cs = CaptureSession(interface=interface)
    session.add(cs)
    session.commit()
    session.refresh(cs)
    session.close()
    return cs


def add_packet_to_session(packet: Packet) -> Packet:
    session = SessionPackets()
    session.add(packet)
    session.commit()
    session.refresh(packet)
    session.close()
    return packet


def get_packets(session_id: int, limit: int = 100) -> List[Packet]:
    session = SessionPackets()
    packets = (
        session.query(Packet)
        .filter(Packet.session_id == session_id)
        .order_by(Packet.timestamp.desc())
        .limit(limit)
        .all()
    )
    session.close()
    return packets


def get_latest_session() -> CaptureSession:
    session = SessionPackets()
    cs = session.query(CaptureSession).order_by(CaptureSession.start_time.desc()).first()
    session.close()
    return cs
