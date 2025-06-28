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

    def match_packet(self, packet: Packet) -> ruleMatched:
        """
        Retourne False dès qu'une règle deny match,
        Sinon True seulement si au moins une règle allow match,
        Sinon False.
        """

        allow_rules = []

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

            if rule["action"].lower() == "deny":
                return ruleMatched(rule=rule, is_valid=False)  # ❌ bloqué

            elif rule["action"].lower() == "allow":
                allow_rules.append(rule)

        if allow_rules:
            return ruleMatched(rule=allow_rules[0], is_valid=True)  # ✅ autorisé

        return ruleMatched(rule={}, is_valid=False)  # 🚫 bloqué par défaut

    def _match_ip(self, ip, cidr):
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)
        except ValueError:
            return False
    def get_rules(self):
        return self.rules
