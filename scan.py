#!/usr/bin/env python3
"""
scan.py — Découverte réseau (Nmap) + corrélation CVE locale + Classification IA hybride

Dépendances :
  sudo apt install nmap
  pip install python-nmap pymongo packaging rapidfuzz transformers torch
  MongoDB « cvedb » rempli par cve-search / CveXplore
  SQLite initialisé via BD/db.py

© 2025
"""
from __future__ import annotations
import argparse, json, os, re, sys
from typing import List, Dict, Any
import nmap
from pymongo import MongoClient
from packaging.version import Version, InvalidVersion
from rapidfuzz import process, fuzz
from BD.scan_db import init_db, save_scan_entry
from ai_local import classify_scan_results  # Import de notre nouveau système

# Initialisation de la base avant toute opération de scan
init_db()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
CVE_DB = "cvedb"

# ─── Helpers ─────────────────────────────────────────────────────────────────
def normalize_version(v: str) -> str:
    v = v or ""
    if m := re.search(r"(\d+\.\d+\.\d+)", v): return m.group(1)
    if m := re.search(r"(\d+\.\d+)", v): return m.group(1)
    return v.strip()

def nmap_args(profile: str, want_cve: bool) -> str:
    match profile:
        case "quick":    return "-sV" if want_cve else "--script nbstat"
        case "standard": return "-O -T4 -sV" if want_cve else "-O -T4"
        case "deep":     return "-A -T4"
        case _:           return "-O -T4"

def categorize(ports: List[int], osn: str) -> str:
    """Catégorisation de base (sera remplacée par l'IA)"""
    osn_low = osn.lower()
    pset = set(ports)
    if 554 in pset or "camera" in osn_low: return "Surveillance"
    if 9100 in pset or "printer" in osn_low: return "Maintenance"
    if pset & {3306, 5432, 27017, 1521, 1433}: return "Database"
    if pset & {80, 443, 8080, 8000, 8443}: return "Web service"
    if 22 in pset or 3389 in pset: return "Remote access"
    if pset & {25, 110, 143, 587, 993, 995}: return "Mail service"
    if 53 in pset: return "DNS"
    if 161 in pset or any(k in osn_low for k in ("iot","device","embedded")): return "Agent IoT"
    if any(k in osn_low for k in ("windows","macos","mac")): return "Endpoint"
    if "linux" in osn_low and pset & {22,80}: return "Endpoint"
    return "Service" if len(pset)>3 else "Endpoint"

def sort_cves(lst: List[str]) -> List[str]:
    return sorted(lst, key=lambda c: int(c.split('-')[1]))

# ─── Classe d'accès CVE ─────────────────────────────────────────────────────────
class LocalCVE:
    def __init__(self, uri=MONGO_URI, db=CVE_DB):
        cli = MongoClient(uri, tz_aware=False)
        self.cpe  = cli[db]["cpe"]
        self.cves = cli[db]["cves"]
        self.known_products = self.cpe.distinct("product")

    @staticmethod
    def _in_rng(ver, si, se, ei, ee) -> bool:
        try:
            v = Version(normalize_version(ver))
        except InvalidVersion:
            return False
        if si  and v <  Version(si): return False
        if se  and v <= Version(se): return False
        if ei  and v >  Version(ei): return False
        if ee  and v >=Version(ee): return False
        return True

    def _fuzzy_product(self, prod: str) -> str:
        raw = prod.lower().strip()
        # exact match
        if raw in self.known_products:
            return raw
        # substring match
        candidates = [k for k in self.known_products if raw in k or k in raw]
        if candidates:
            return max(candidates, key=lambda k: fuzz.partial_ratio(raw, k))
        # fuzzy fallback
        match = process.extractOne(raw, self.known_products, scorer=fuzz.partial_ratio, score_cutoff=80)
        return match[0] if match else raw

    def _cpe_names(self, prod: str, ver: str) -> List[str]:
        if not prod or not ver: return []
        p = self._fuzzy_product(prod)
        v = normalize_version(ver)
        # primaire
        q = {"product":{"$regex":re.escape(p),"$options":"i"},
             "$or":[{"version":v},{"padded_version":v},
                     {"version":{"$exists":False},
                      "padded_version":{"$exists":False}}]}
        res = [d["cpeName"] for d in self.cpe.find(q,{"cpeName":1})]
        if res: return res
        # fallback vendor
        vendors = self.cpe.distinct("vendor")
        vm = process.extractOne(prod, vendors, score_cutoff=80)
        vendor = vm[0] if vm else prod.lower().split()[0]
        regex = f":{vendor}:.*:{re.escape(v)}:"
        fb = self.cpe.find({"cpeName":{"$regex":regex,"$options":"i"}},{"cpeName":1})
        return [d["cpeName"] for d in fb]

    def cves_for(self, prod: str, ver: str) -> List[str]:
        if not prod or not ver: return []
        cp_list = self._cpe_names(prod, ver)
        found = set()
        # 1) vulnerable_product
        for cp in cp_list:
            for d in self.cves.find({"vulnerable_product":cp},{"id":1}):
                found.add(d["id"])
        # 2) configurations exact
        for cp in cp_list:
            for doc in self.cves.find({"configurations.nodes.cpe_match":
                        {"$elemMatch":{"cpe23Uri":cp,"vulnerable":True}}},
                        {"id":1,"configurations.nodes.cpe_match":1}):
                cid = doc["id"]
                for n in doc.get("configurations",{}).get("nodes",[]):
                    for cm in n.get("cpe_match",[]):
                        if cm.get("cpe23Uri")==cp and cm.get("vulnerable") and \
                           self._in_rng(ver, cm.get("versionStartIncluding"), cm.get("versionStartExcluding"), \
                                            cm.get("versionEndIncluding"), cm.get("versionEndExcluding")):
                            found.add(cid)
                            break
        # 3) range fallback
        qname = re.escape(self._fuzzy_product(prod))
        for doc in self.cves.find({"configurations.nodes.cpe_match.cpe23Uri":
                        {"$regex":qname,"$options":"i"}}, {"id":1,"configurations.nodes.cpe_match":1}):
            cid = doc["id"]
            for n in doc.get("configurations",{}).get("nodes",[]):
                for cm in n.get("cpe_match",[]):
                    if cm.get("vulnerable") and re.search(qname,cm.get("cpe23Uri",""),re.I) and \
                       self._in_rng(ver, cm.get("versionStartIncluding"), cm.get("versionStartExcluding"), \
                                        cm.get("versionEndIncluding"), cm.get("versionEndExcluding")):
                        found.add(cid)
                        break
        return sort_cves(list(found))

# ─── Programme principal ───────────────────────────────────────────────────────
def main() -> None:
    pa = argparse.ArgumentParser("Scan réseau + CVE locales + IA hybride")
    pa.add_argument("scan_type", choices=["quick","standard","deep"])
    pa.add_argument("target",    help="IP ou CIDR (ex : 192.168.1.0/24)")
    pa.add_argument("-p","--ports", help="Ports Nmap (ex : 80,8080)", default=None)
    pa.add_argument("-v","--vuln",  action="store_true", help="Activer recherche CVE")
    pa.add_argument("-a","--ai",    action="store_true", help="Activer classification IA", default=True)
    pa.add_argument("-d","--debug", action="store_true")
    a = pa.parse_args()

    if os.geteuid()!=0: sys.exit("[❌] Lance avec sudo")

    nm = nmap.PortScanner()
    nm.scan(hosts=a.target, arguments="-sn --host-timeout 30s")
    live = nm.all_hosts()
    if not live: sys.exit("[⚠️] Aucun hôte actif.")

    nm2 = nmap.PortScanner()
    arg = nmap_args(a.scan_type, a.vuln)
    if a.ports: arg += f" -p {a.ports}"
    scan_args = f"{arg} --host-timeout 2m"
    print(f"[🔍] Scan {a.scan_type} sur {a.target} (args : {scan_args})")
    print(f"[📡] Hôtes : {', '.join(live)}")
    print(f"[🤖] Classification IA : {'Activée' if a.ai else 'Désactivée'}")
    
    nm2.scan(hosts=" ".join(live), arguments=scan_args)

    cdb = LocalCVE() if a.vuln else None
    res: List[Dict[str,Any]] = []
    
    for ip in nm2.all_hosts():
        n = nm2[ip]; r = {"ip":ip}
        if n.get("hostnames"): r["hostname"] = n["hostnames"][0]["name"]

        if a.scan_type=="quick":
            for s in n.get("hostscript",[]):
                if s["id"]=="nbstat": r["netbios"]=s["output"]
            # Catégorisation basique pour quick scan
            r["os"] = "Unknown"
            r["role"] = "Endpoint"
            res.append(r); continue

        ports = list(n.get("tcp",{}).keys()); r["ports"]=ports
        osm   = n.get("osmatch") or []
        osn   = osm[0].get("name","Unknown") if osm else "Unknown"
        r["os"]   = osn
        
        # Catégorisation de base (sera affinée par l'IA)
        r["role"] = categorize(ports,osn)

        sv: List[Dict[str,Any]] = []
        print(f"\n[SCAN] {ip}:")
        for p in ports:
            d = n["tcp"][p]
            prod = d.get("product","")
            ver  = d.get("version","")
            name = d.get("name","")
            cves = cdb.cves_for(prod,ver) if cdb else []
            if a.debug:
                print(f"  Port {p:<5} : {name:<15} {prod:<20} {ver:<15} → {len(cves)} CVE")
            # Champ 'info' pour l'affichage
            info = f"{prod or name} {ver}".strip()
            sv.append({
                "port": p,
                "name": name,
                "product": prod,
                "version": ver,
                "cves": cves,
                "info": info
            })
        r["services"] = sv
        res.append(r)

    # Classification IA hybride
    if a.ai:
        print("\n[🤖] Application de la classification IA hybride...")
        res = classify_scan_results(res)
        
        # Affichage des résultats IA
        print("\n[📊] Résultats de classification :")
        for r in res:
            ai_type = r.get("device_type", r.get("type", "?"))
            ai_score = r.get("ai_score", 0)
            print(f"  {r['ip']:<15} → {ai_type:<20} (confiance: {ai_score:.2%})")

    out = {"quick":"resultatrapide.json","standard":"resultatmoyen.json","deep":"resultatapprofondie.json"}[a.scan_type]
    json.dump(res, open(out,"w"), indent=4,ensure_ascii=False)
    open("lastscan.txt","w").write(out)
    
    try: 
        save_scan_entry(a.scan_type,res)
        print(f"\n[✅] Scan terminé → {out} (BD mise à jour)")
    except Exception as e: 
        print(f"[⚠️] DB : {e}")

if __name__ == "__main__": main()