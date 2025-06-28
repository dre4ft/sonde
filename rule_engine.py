import ipaddress
import json
from dataclasses import dataclass
from typing import Optional

@dataclass
class Packet:
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None


@dataclass
class ruleMatched:
    rule: dict
    is_valid: bool

class RulesEngine:

    def __init__(self, rules_file="rules.json"):
        with open(rules_file, "r") as f:
            self.rules = json.load(f)["rules"]

    def match_packet(self, packet : Packet) -> ruleMatched:
        """
        Retourne False si une règle deny est violée.
        Sinon True.
        """

        for rule in self.rules:
            # Protocole
            if rule.get("protocol") and rule["protocol"].upper() != packet.protocol.upper():
                continue

            # IPs
            if not self._match_ip(packet.src_ip, rule["src_ip"]):
                continue
            if not self._match_ip(packet.dst_ip, rule["dst_ip"]):
                continue

            # Ports
            if "src_port" in rule and packet.src_port != rule["src_port"]:
                continue
            if "dst_port" in rule and packet.dst_port != rule["dst_port"]:
                continue

            if rule["action"] == "deny":
                return ruleMatched(rule=rule,is_valid=False)# ❌ paquet bloqué

        return ruleMatched(rule={},is_valid=True)  # ✅ rien n'a bloqué le paquet

    def _match_ip(self, ip, cidr):
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)
        except ValueError:
            return False
    def get_rules(self):
        return self.rules
