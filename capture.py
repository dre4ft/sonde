import threading
import json
from scapy.all import sniff, IP, TCP, UDP
from BD.packet_db import create_capture_session, add_packet_to_session, get_latest_session
from rule_engine import RulesEngine, Packet

_stop_event = threading.Event()
_capture_thread = None
_current_session_id = None
_rules_engine = None  # Initialisé au démarrage

# Charger les règles une fois
def load_rules(path="rules.json"):
    return RulesEngine(path)

def process_packet(pkt):
    if IP in pkt:
        ip_layer = pkt[IP]
        proto = None
        sport = None
        dport = None

        if TCP in pkt:
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        else:
            proto = str(ip_layer.proto)

        raw_summary = pkt.summary()

        # Création d'un objet Packet pour l'analyse des règles
        p = Packet(
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            protocol=proto,
            src_port=sport,
            dst_port=dport
        )

        rule_matched = _rules_engine.match_packet(p)  # True si le paquet est autorisé

        # Ajoute le paquet à la session en cours
        if _current_session_id is not None:
            add_packet_to_session(
                session_id=_current_session_id,
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                protocol=proto,
                src_port=sport,
                dst_port=dport,
                raw=raw_summary,
                rule_matched=rule_matched
            )
        print(f"Packet capturé: {raw_summary} | Valide: {rule_matched}")

def _sniff_thread(interface):
    sniff(iface=interface, prn=process_packet, store=0, stop_filter=lambda x: _stop_event.is_set())

def start_capture(interface="lo0"):
    global _capture_thread, _stop_event, _current_session_id, _rules_engine

    if _capture_thread and _capture_thread.is_alive():
        print("Capture déjà en cours.")
        return False

    _stop_event.clear()

    # Charger règles au démarrage
    _rules_engine = load_rules()

    # Créer une nouvelle session de capture dans la DB
    session = create_capture_session(interface)
    _current_session_id = session.id

    _capture_thread = threading.Thread(target=_sniff_thread, args=(interface,), daemon=True)
    _capture_thread.start()
    print(f"Capture démarrée sur {interface}, session id: {_current_session_id}")
    return True

def stop_capture():
    global _stop_event, _capture_thread, _current_session_id
    _stop_event.set()
    if _capture_thread:
        _capture_thread.join()
    _capture_thread = None
    _current_session_id = None
    print("Capture arrêtée.")

def get_rules():
    global _rules_engine
    if _rules_engine is not None:
        return _rules_engine.get_rules()
  
