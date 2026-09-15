"""
seed_alerts.py
==============
Alertes Wazuh synthétiques (mais construites sur des rule.id/groups/MITRE réels et
plausibles du ruleset Wazuh) utilisées pour compléter le dataset public kholil-lil/wazuh-alerts.

Pourquoi ce fichier existe : le dataset public (738 alertes) ne contient AUCUN exemple
des catégories "malware", "recon", "endpoint" et "network" une fois passé par la taxonomie
de src/attack_category.py (voir data/processed/training_data.csv après conversion) — un
modèle entraîné dessus ne pourrait tout simplement jamais reconnaître ces menaces, quelle
que soit sa qualité. Ce module fournit un jeu d'alertes générées à partir de gabarits
correspondant à des règles Wazuh réelles (mêmes rule.id/groups que ceux déjà utilisés
ailleurs dans ce projet, ex: api.py::_SAMPLE_ALERTS, ou observés en trafic réel pendant le
développement, ex: rule 61071 "MS SQL server logon failure"), avec variation d'agent/IP/
horodatage/firedtimes pour donner au Random Forest suffisamment d'exemples distincts par
catégorie sans pour autant les dupliquer à l'identique.

Ce n'est PAS un remplacement d'un vrai dataset labellisé : c'est un correctif de couverture,
à retirer/réduire dès que des alertes réelles labellisées par les analystes du SOC cible
sont disponibles pour ces catégories (voir README, section Roadmap).

Usage :
    from src.seed_alerts import generate_seed_alerts
    alerts = generate_seed_alerts()   # -> List[{"raw": {...alerte Wazuh...}, "label": 0|1}]
"""

from __future__ import annotations

import random
from typing import Any, Dict, List

_AGENTS = [
    ("003", "web-srv-01"), ("004", "win-workstation-07"), ("005", "win-workstation-12"),
    ("006", "dc-01"), ("002", "ubuntu-agent-115"), ("007", "file-srv-02"),
]
_IPS = [
    "185.220.101.45", "45.155.205.20", "91.240.118.222", "194.26.29.13",
    "103.145.13.8", "172.17.1.115", "172.17.1.120", "10.212.1.254",
]

# Gabarits : (rule_id, level, description, groups, mitre_ids, mitre_tactics, label_TP)
_TEMPLATES: List[tuple] = [
    # --- malware ---------------------------------------------------------------------
    (87105, 12, "VirusTotal: Malware detected in file (positive detections: {n}/68).",
     ["virustotal", "syscheck", "malware"], ["T1204"], ["Execution"], 1),
    (100301, 12, "AbuseIPDB/VirusTotal: known malware C2 hash matched on endpoint.",
     ["malware", "virustotal"], ["T1105"], ["Command and Control"], 1),
    (510, 3, "Host-based anomaly detection event (rootcheck): trojaned binary suspected.",
     ["rootcheck", "malware"], ["T1055"], ["Defense Evasion"], 1),
    (554, 7, "File added to the system and flagged by antivirus signature.",
     ["syscheck", "malware"], ["T1204.002"], ["Execution"], 1),
    # --- recon -------------------------------------------------------------------------
    (100050, 6, "Multiple TCP SYN packets to sequential ports from same source (port scan).",
     ["recon", "attack"], ["T1046"], ["Reconnaissance"], 1),
    (100051, 5, "Nmap-like scanning signature detected (service enumeration).",
     ["recon"], ["T1595"], ["Reconnaissance"], 1),
    (31151, 4, "Multiple 404 errors from same source (web directory brute-forcing / recon).",
     ["web", "recon"], ["T1595.003"], ["Reconnaissance"], 1),
    (100052, 3, "DNS zone transfer attempt detected.",
     ["recon", "attack"], ["T1590.002"], ["Reconnaissance"], 1),
    # --- endpoint (Windows / Sysmon / PowerShell) --------------------------------------
    (60122, 10, "PowerShell script block logged (obfuscated content detected).",
     ["windows", "powershell"], ["T1059.001"], ["Execution"], 1),
    (92050, 9, "Sysmon - Process creation from suspicious parent (living-off-the-land binary).",
     ["windows", "sysmon"], ["T1055"], ["Defense Evasion"], 1),
    (92051, 7, "Sysmon - Registry key modified for persistence (Run key).",
     ["windows", "sysmon"], ["T1547.001"], ["Persistence"], 1),
    (18152, 3, "Windows: scheduled task created by non-admin user.",
     ["windows"], ["T1053.005"], ["Persistence"], 0),
    # --- network / firewall -------------------------------------------------------------
    (651, 3, "pfSense: Firewall rule match, connection blocked (routine noise).",
     ["firewall"], [], [], 0),
    (4501, 8, "pfSense: Multiple denied connections to sensitive internal service.",
     ["firewall", "attack"], ["T1046"], ["Reconnaissance"], 1),
    (4502, 3, "pfSense: Outbound connection allowed to known-good CDN endpoint.",
     ["firewall"], [], [], 0),
    (100200, 12, "AbuseIPDB: malicious IP detected in inbound traffic.",
     ["attack", "firewall"], ["T1071"], ["Command and Control"], 1),
    # --- sql (renforcement, seulement 9 exemples dans le dataset public) ----------------
    (31151, 8, "Web attack detected: SQL injection attempt (' OR '1'='1 pattern in request).",
     ["attack", "web"], ["T1190"], ["Initial Access"], 1),
    (61071, 5, "MS SQL server logon failure.",
     ["mssql", "authentication_failed"], [], [], 1),
    (61072, 3, "MS SQL server successful logon (informational, routine service account).",
     ["mssql"], [], [], 0),
    (100400, 11, "SQL Server: suspicious xp_cmdshell execution detected after logon.",
     ["mssql", "attack"], ["T1505.001"], ["Persistence"], 1),
    (100401, 9, "MySQL: UNION-based SQL injection payload detected in query log.",
     ["mysql", "sql_injection", "attack"], ["T1190"], ["Initial Access"], 1),
    (100402, 3, "PostgreSQL: routine administrative query logged (pg_dump backup job).",
     ["postgresql", "database"], [], [], 0),
    # --- vulnerability (module vulnerability-detector Wazuh / CVE explicite) -----------
    # Catégorie absente du dataset public ET sans aucun gabarit avant cet ajout : le modèle
    # de catégorie ne pouvait donc JAMAIS prédire "vulnerability" malgré sa présence dans
    # la taxonomie (src/attack_category.py) — voir README section 9/10.
    (23503, 7, "Vulnerability-detector: CVE-2023-23397 (Microsoft Outlook privilege escalation) "
     "found in installed package.", ["vulnerability-detector"], [], [], 1),
    (23504, 5, "Vulnerability-detector: outdated OpenSSL package vulnerable to CVE-2022-3602 detected.",
     ["vulnerability-detector"], [], [], 1),
    (23505, 10, "Vulnerability-detector: critical vulnerability CVE-2021-44228 (Log4Shell) "
     "found in installed application.", ["vulnerability-detector"], ["T1190"], ["Initial Access"], 1),
    (23506, 6, "Vulnerability-detector: medium severity vulnerability CVE-2020-1472 (Zerologon) "
     "detected on domain controller.", ["vulnerability-detector"], ["T1068"], ["Privilege Escalation"], 1),
    (23507, 3, "Vulnerability-detector: package scan completed, no new vulnerabilities found (routine).",
     ["vulnerability-detector"], [], [], 0),
    (23508, 8, "Vulnerability-detector: exploit available for outdated Apache Struts version, "
     "unpatched since {n} days.", ["vulnerability-detector"], ["T1190"], ["Initial Access"], 1),
    # --- ddos (déni de service, distinct du brute force mono-cible) --------------------
    # Catégorie absente du dataset public ET sans aucun gabarit avant cet ajout (même
    # problème que "vulnerability" ci-dessus).
    (100500, 11, "pfSense: SYN flood detected from multiple distinct source IPs targeting web server.",
     ["firewall", "ddos"], ["T1498"], ["Impact"], 1),
    (100501, 12, "Web server: HTTP flood detected, excessive number of connections from distributed sources.",
     ["web", "dos"], ["T1498.001"], ["Impact"], 1),
    (100502, 10, "Network: UDP amplification attack detected on inbound traffic.",
     ["firewall", "ddos"], ["T1498.002"], ["Impact"], 1),
    (100503, 9, "IDS: Slowloris-style connection exhaustion attack detected against web-srv.",
     ["web", "dos"], ["T1499"], ["Impact"], 1),
    (100504, 3, "pfSense: temporary connection spike during scheduled backup window (routine, expected load).",
     ["firewall"], [], [], 0),
    # --- bruit / faible signal (renforce is_low_signal pour mieux ignorer les alertes ---
    # inutiles : rotation de logs, connexions/déconnexions d'agent, événements informationnels
    # sans lien avec une menace — cf. demande de réduire la fatigue d'alerte).
    (591, 0, "Log file rotated.", ["ossec"], [], [], 0),
    (502, 1, "New ossec-agent connected.", ["ossec"], [], [], 0),
    (503, 1, "New ossec-agent disconnected.", ["ossec"], [], [], 0),
    (1002, 2, "Unknown problem somewhere in the system (informational, no actionable signal).",
     ["syslog"], [], [], 0),
    (5501, 2, "Wazuh manager: configuration reloaded (routine, no attack signal).",
     ["ossec"], [], [], 0),
]


def generate_seed_alerts(variations_per_template: int = 4, seed: int = 42) -> List[Dict[str, Any]]:
    """
    Génère `variations_per_template` alertes par gabarit (agent/IP/firedtimes variés,
    déterministe via `seed` pour la reproductibilité), sous la forme attendue par
    parse_wazuh.parse_alert (alerte Wazuh brute) accompagnée de son label TP/FP.

    Retourne une liste de {"raw": <alerte Wazuh brute>, "label": 0|1}.
    """
    rng = random.Random(seed)
    out: List[Dict[str, Any]] = []

    for rule_id, level, desc_template, groups, mitre_ids, mitre_tactics, label in _TEMPLATES:
        for _ in range(variations_per_template):
            agent_id, agent_name = rng.choice(_AGENTS)
            description = desc_template.format(n=rng.randint(5, 60))
            raw = {
                "rule": {
                    "id": rule_id,
                    "level": level,
                    "description": description,
                    "groups": groups,
                    "mitre": {"id": mitre_ids, "tactic": mitre_tactics},
                    "firedtimes": rng.randint(1, 15),
                },
                "agent": {"id": agent_id, "name": agent_name},
                "data": {"srcip": rng.choice(_IPS), "dstip": rng.choice(_IPS)},
                "timestamp": None,
            }
            out.append({"raw": raw, "label": label})

    return out


if __name__ == "__main__":
    from collections import Counter

    from src.attack_category import derive_category
    from src.parse_wazuh import parse_alert

    seeds = generate_seed_alerts()
    cats = Counter(derive_category(parse_alert(s["raw"])) for s in seeds)
    print(f"{len(seeds)} alertes générées, répartition par catégorie : {dict(cats)}")
