"""
fetch_wazuh_ruleset.py
=======================
Récupère et labellise (heuristiquement) un sous-ensemble du **ruleset officiel Wazuh**
(dépôt public GitHub `wazuh/wazuh-ruleset`, licence GPLv2) pour enrichir les données
d'entraînement avec de VRAIS `rule.id`/`rule.level`/`rule.description`/`rule.groups`/MITRE,
au lieu des identifiants approximatifs de `src/seed_alerts.py`.

Pourquoi ce script plutôt qu'un dataset HuggingFace supplémentaire ? Recherche effectuée
sur le Hub HF (juillet 2026) : `ruf0x/wazuh-alerts` et `wy777/wazuh-alerts` sont des
**doublons exacts** de `kholil-lil/wazuh-alerts` (mêmes 738 lignes, même schéma) — aucune
valeur ajoutée. `yonatane22-bh/sereniq-wazuh-alerts` (10 000 lignes) s'est révélé être un
jeu **entièrement synthétique/templaté** : seulement 54 `rule_id` distincts répétés, et le
label `triage_label` est **déterministe** à partir de `(rule_level, is_known_bad_ip)` pour
12 des 13 combinaisons observées (vérifié via `datasets.load_dataset` + `groupby`) — le
fusionner en masse (10k vs 890 lignes actuelles) aurait dilué le signal réel et biaisé le
modèle vers un raccourci trivial déjà capturé par nos propres features (`rule_level`).
`acezxn/event_correlation_wazuh` contient de vraies alertes Wazuh mais son label `output`
sert à une tâche différente (pertinence d'une étape d'investigation recommandée par un LLM),
pas au triage TP/FP — l'utiliser comme label TP/FP serait un mislabelling. Voir le rapport
de session pour le détail. Conclusion : la ressource la plus fiable et la mieux alignée avec
le schéma du projet est le ruleset Wazuh officiel lui-même (métadonnées de règles réelles,
pas des alertes), d'où ce script.

Ce que ce script fait :
  1. Télécharge (et cache dans data/raw/wazuh_ruleset/) une sélection de fichiers XML du
     ruleset officiel, choisis pour couvrir la taxonomie du projet (sql, malware, bruteforce,
     ddos, vulnerability, recon, web, endpoint, network — voir src/attack_category.py).
  2. Parse chaque <rule> (id, level, description(s), groupes hérités du <group name="..">
     englobant + groupes propres, MITRE).
  3. Réutilise `src/attack_category.derive_category` (déjà la source de vérité du projet)
     pour catégoriser chaque règle — pas de mapping dupliqué à maintenir.
  4. Applique un label TP/FP heuristique **volontairement conservateur** : les règles dont le
     sens est ambigu (pas de groupe/MITRE clairement indicateur de menace, niveau moyen 3-9,
     pas de mot-clé de bruit routinier) sont **exclues** plutôt que devinées, pour ne pas
     dégrader la qualité du dataset (contrairement au but recherché). Voir `_label_rule()`
     pour le détail exact des règles.
  5. Écrit le résultat dans data/raw/wazuh_ruleset_rules.json (un objet par règle retenue),
     consommé ensuite par `generate_ruleset_alerts()` (même mécanique de variation
     agent/IP/firedtimes que `src/seed_alerts.generate_seed_alerts`).

Usage :
    python -m src.fetch_wazuh_ruleset                 # télécharge + parse + écrit le JSON
    python -m src.fetch_wazuh_ruleset --offline        # reparse le cache XML local existant
"""

from __future__ import annotations

import argparse
import json
import random
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

RAW_URL = "https://raw.githubusercontent.com/wazuh/wazuh-ruleset/master/rules/{}"
CACHE_DIR = Path("data/raw/wazuh_ruleset")
OUTPUT_PATH = Path("data/raw/wazuh_ruleset_rules.json")

# Fichiers choisis pour couvrir la taxonomie du projet (voir src/attack_category.py) sans
# télécharger l'intégralité des 135 fichiers du ruleset (hors-périmètre : mail, imprimantes,
# VPN concentrators, etc. non pertinents pour ce SOC).
RULE_FILES: List[str] = [
    # bruteforce / auth
    "0085-pam_rules.xml", "0095-sshd_rules.xml", "0685-macos-sshd_rules.xml",
    "0220-msauth_rules.xml", "0580-win-security_rules.xml",
    # sql / bases de données
    "0295-mysql_rules.xml", "0300-postgresql_rules.xml", "0440-ms_sqlserver_rules.xml",
    "0450-mongodb_rules.xml", "0530-mysql_audit_rules.xml", "0535-mariadb_rules.xml",
    "0380-redis_rules.xml",
    # malware / EDR
    "0490-virustotal_rules.xml", "0320-clam_av_rules.xml", "0430-ms_wdefender_rules.xml",
    "0600-win-wdefender_rules.xml", "0485-cylance_rules.xml", "0550-kaspersky_rules.xml",
    # vulnerability / audit de conformité
    "0520-vulnerability-detector_rules.xml", "0505-vuls_rules.xml", "0525-openvas_rules.xml",
    "0480-qualysguard_rules.xml", "0385-oscap_rules.xml",
    # recon / IDS / attaque générique
    "0240-ids_rules.xml", "0475-suricata_rules.xml", "0280-attack_rules.xml",
    # web
    "0245-web_rules.xml", "0270-web_appsec_rules.xml", "0250-apache_rules.xml",
    "0260-nginx_rules.xml", "0145-wordpress_rules.xml",
    # endpoint (windows / sysmon)
    "0330-sysmon_rules.xml", "0595-win-sysmon_rules.xml", "0575-win-base_rules.xml",
    "0620-win-generic_rules.xml",
    # réseau / pare-feu / ddos
    "0060-firewall_rules.xml", "0540-pfsense_rules.xml", "0290-firewalld_rules.xml",
    "0625-cisco-asa_rules.xml", "0700-paloalto_rules.xml",
]

# Mots-clés indiquant une alerte purement informationnelle/routinière (pas un incident) —
# utilisés pour labelliser en False Positive les règles de faible sévérité au contenu clair.
_NOISE_KEYWORDS = re.compile(
    r"\b(grouped|informational|started|stopped|starting up|successful login|login success|"
    r"session opened|session closed|no records|healthy|routine|process id|loaded|unloaded)\b",
    re.IGNORECASE,
)

# Groupes considérés comme indicateurs directs d'une activité malveillante/suspecte —
# alignés sur les groupes déjà surveillés par src/feature_engineering.py (WATCHED_GROUPS).
_THREAT_GROUPS = {
    "attack", "recon", "malware", "sql_injection", "sqli", "authentication_failed",
    "authentication_failures", "web_scan", "vulnerability-detector", "invalid_login",
    "multiple_drops", "firewall_drop",
}

# Diagnostics internes d'un logiciel (moteur AV en erreur, base de signatures corrompue,
# scan interne requis...) : souvent à niveau élevé (12+) dans le ruleset car ils nécessitent
# une action IT urgente, MAIS ce n'est PAS un signal d'attaque détectée — les confondre avec
# un vrai incident biaiserait le label TP. Repéré lors du spot-check (ex: rule 62199 "Windows
# Defender: ERROR: BAD USER DB VERSION", level 12, sans MITRE) : exclues plutôt que labellisées,
# même logique de prudence que le reste de _label_rule.
_SELFDIAG_KEYWORDS = re.compile(
    r"\berror:|encountered an error|bad (db|user db|scan id)|scan required|"
    r"platform (is running|will soon)|engine (downloaded|was downloaded)",
    re.IGNORECASE,
)


def _fetch_file(name: str, offline: bool) -> Optional[str]:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = CACHE_DIR / name
    if offline or cache_path.exists():
        if cache_path.exists():
            return cache_path.read_text(encoding="utf-8")
        if offline:
            return None

    import requests

    try:
        res = requests.get(RAW_URL.format(name), timeout=15)
        res.raise_for_status()
    except requests.RequestException as exc:
        print(f"[fetch_wazuh_ruleset] AVERTISSEMENT : échec de téléchargement de {name} ({exc}), ignoré.")
        return None
    cache_path.write_text(res.text, encoding="utf-8")
    return res.text


# Substitution des champs interpolés `$(field.name)` (syntaxe Wazuh) par des valeurs
# plausibles, pour que le texte de description soit exploitable par les features texte
# (has_sqli_pattern, has_cve_pattern, mots-clés) au lieu de rester un gabarit brut. Construite
# en énumérant tous les placeholders réellement présents dans les fichiers ciblés (voir
# RULE_FILES) — toute règle dont un placeholder n'est PAS couvert ici est exclue par
# _resolve_description (retourne None) plutôt que de laisser un nom de champ brut comme texte
# (ex: "severity severity log on device_name" observé lors du premier passage, corrigé ici).
_FIELD_SUBSTITUTIONS = {
    "vulnerability.cve": "CVE-2024-21412",
    "vulnerability.package.name": "openssl",
    "vulnerability.severity": "High",
    "srcip": "203.0.113.42",
    "dstuser": "svc_account",
    "user": "jdoe",
    "win.eventdata.image": "C:\\Windows\\Temp\\payload.exe",
    "win.eventdata.commandLine": "powershell -enc SQBFAFgA",
    "win.eventdata.sourceImage": "C:\\Windows\\System32\\rundll32.exe",
    "oscap.check.title": "SSH Idle Timeout Interval",
    "device_name": "fw-edge-01",
    "qualysguard.vulnerability_title": "Apache HTTP Server Multiple Vulnerabilities",
    "vuls.scanned_cve": "CVE-2024-21412",
    "win.eventdata.memberSid": "S-1-5-21-1111111111-2222222222-3333333333-1105",
    "severity": "high",
    "description": "unauthorized configuration change detected",
    "cylance_events.filepath": "C:\\Users\\Public\\update.exe",
    "cylance_threats.file_path": "C:\\Users\\Public\\update.exe",
    "vuls.assurance": "Confirmed",
    "vuls.detection_method": "package version comparison",
    "vuls.source": "NVD",
    "vuls.affected_packages": "openssl 1.1.1",
    "audit_record.command_class": "privileged",
    "cmd": "/bin/bash -c 'id'",
    "win.eventdata.path": "C:\\Windows\\Temp\\payload.exe",
    "win.eventdata.processName": "powershell.exe",
    "vuls.scan_date": "2026-07-01",
    "vuls.tittle": "Remote Code Execution in openssl",
    "vuls.score": "9.8",
    "src_ip": "203.0.113.42",
    "dst_ip": "172.17.1.115",
    "session_end_reason": "threat-detected",
    "virustotal.source.file": "invoice.pdf.exe",
    "win.eventdata.severityName": "High",
    "win.eventdata.feature": "Real-Time Protection",
    "action": "deny",
    "alert.signature": "ET MALWARE Generic Trojan Callback",
    "virustotal.positives": "42",
    "vuls.days": "180",
    "vuls.core": "9.1",
    "TaskName": "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan",
    "TaskState": "Disabled",
    "win.eventdata.description": "Scheduled task was disabled",
    "win.eventdata.detectionType": "Behavioral",
    "win.eventdata.failureType": "Access denied",
    "win.eventdata.resource": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "win.eventdata.errorCode": "0x80070005",
}
_FIELD_PATTERN = re.compile(r"\$\(([\w.]+)\)")


def _resolve_description(text: str) -> Optional[str]:
    """Retourne None (règle à exclure) si un placeholder `$(...)` n'a pas de substitution
    connue, plutôt que de produire un texte contenant le nom de champ brut."""
    missing: List[str] = []

    def repl(m: "re.Match[str]") -> str:
        key = m.group(1)
        if key not in _FIELD_SUBSTITUTIONS:
            missing.append(key)
            return ""
        return _FIELD_SUBSTITUTIONS[key]

    resolved = _FIELD_PATTERN.sub(repl, text)
    if missing:
        return None
    return resolved


def _parse_file(xml_text: str, source_file: str) -> List[Dict[str, Any]]:
    wrapped = f"<root>{xml_text}</root>"
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError as exc:
        print(f"[fetch_wazuh_ruleset] AVERTISSEMENT : {source_file} non parseable ({exc}), ignoré.")
        return []

    rules: List[Dict[str, Any]] = []

    def walk(node: ET.Element, inherited_groups: List[str]) -> None:
        for child in node:
            if child.tag == "group" and child.get("name") is not None:
                own = [g.strip() for g in (child.get("name") or "").split(",") if g.strip()]
                walk(child, inherited_groups + own)
            elif child.tag == "rule":
                rules.append(_parse_rule(child, inherited_groups, source_file))

    walk(root, [])
    return rules


def _parse_rule(rule_el: ET.Element, inherited_groups: List[str], source_file: str) -> Dict[str, Any]:
    rule_id = rule_el.get("id", "")
    try:
        level = int(rule_el.get("level", "0"))
    except ValueError:
        level = 0

    descriptions = [d.text.strip() for d in rule_el.findall("description") if d.text and d.text.strip()]
    description = _resolve_description(" ".join(descriptions)) or ""

    own_groups: List[str] = []
    for g_el in rule_el.findall("group"):
        if g_el.text:
            own_groups.extend(g.strip() for g in g_el.text.split(",") if g.strip())

    groups = sorted(set(inherited_groups) | set(own_groups))
    # Ne garder que le préfixe avant "_" pour les tags de conformité verbeux
    # (pci_dss_11.4, gdpr_IV_35.7.d, ...) serait trop agressif et casserait des groupes
    # légitimes à underscore (authentication_failed) : on les laisse tels quels, ils sont
    # simplement ignorés par WATCHED_GROUPS/attack_category côté aval (pas de faux signal).

    mitre_ids = [m.text.strip() for m in rule_el.findall("./mitre/id") if m.text]

    return {
        "rule_id": rule_id,
        "level": level,
        "description": description,
        "groups": groups,
        "mitre_ids": mitre_ids,
        "source_file": source_file,
    }


def _label_rule(rule: Dict[str, Any]) -> Optional[int]:
    """
    Label TP(1)/FP(0) heuristique et CONSERVATEUR : renvoie None (règle exclue) plutôt
    qu'un label deviné pour les cas ambigus, afin de protéger la qualité du dataset final.

        - diagnostic interne logiciel (_SELFDIAG_KEYWORDS) SANS MITRE     -> exclue (None)
        - has_mitre OU groupe dans _THREAT_GROUPS                        -> TP (1)
        - level >= 10 (convention Wazuh : sévérité élevée/critique)      -> TP (1)
        - level <= 2                                                     -> FP (0)
        - mot-clé de bruit routinier (_NOISE_KEYWORDS) ET level <= 5     -> FP (0)
        - sinon (zone grise 3-9 sans signal clair)                       -> exclue (None)
    """
    groups = set(rule["groups"])
    description = rule["description"] or ""
    level = rule["level"]

    if not rule["mitre_ids"] and _SELFDIAG_KEYWORDS.search(description):
        return None
    if rule["mitre_ids"] or (groups & _THREAT_GROUPS):
        return 1
    if level >= 10:
        return 1
    if level <= 2:
        return 0
    if _NOISE_KEYWORDS.search(description) and level <= 5:
        return 0
    return None


def build_ruleset_dataset(offline: bool = False) -> List[Dict[str, Any]]:
    from src.attack_category import derive_category

    all_rules: List[Dict[str, Any]] = []
    for fname in RULE_FILES:
        xml_text = _fetch_file(fname, offline)
        if xml_text is None:
            continue
        all_rules.extend(_parse_file(xml_text, fname))

    labelled: List[Dict[str, Any]] = []
    seen_ids: set = set()
    for rule in all_rules:
        # niveau 0 = règles "grouped"/décodeur de base, jamais réellement alertées par Wazuh
        # (cohérent avec le seuil <level>3</level> déjà utilisé pour l'intégration, section 7.2
        # du README) — on les exclut d'office, label ou pas.
        if rule["level"] <= 0:
            continue
        if not rule["description"]:
            continue
        if rule["rule_id"] in seen_ids:
            continue  # certains id apparaissent dans plusieurs fichiers (overrides), 1er gagne

        label = _label_rule(rule)
        if label is None:
            continue

        pseudo_record = {
            "rule_groups": rule["groups"],
            "rule_description": rule["description"],
            "mitre_ids": rule["mitre_ids"],
            "mitre_tactics": [],
            "text_blob": rule["description"],
        }
        category = derive_category(pseudo_record)

        seen_ids.add(rule["rule_id"])
        labelled.append({**rule, "label": label, "category": category})

    return labelled


def generate_ruleset_alerts(rules: List[Dict[str, Any]], variations_per_rule: int = 2, seed: int = 7) -> List[Dict[str, Any]]:
    """
    Même mécanique que src/seed_alerts.generate_seed_alerts : transforme chaque règle
    labellisée en `variations_per_rule` alertes Wazuh brutes (agent/IP/firedtimes variés),
    pour que rule_freq_5min/distinct_srcip_5min aient de la variance au lieu d'une valeur
    constante. Retourne une liste de {"raw": {...}, "label": 0|1}.
    """
    _AGENTS = [
        ("003", "web-srv-01"), ("004", "win-workstation-07"), ("005", "win-workstation-12"),
        ("006", "dc-01"), ("002", "ubuntu-agent-115"), ("007", "file-srv-02"), ("008", "db-srv-03"),
    ]
    _IPS = [
        "185.220.101.45", "45.155.205.20", "91.240.118.222", "194.26.29.13",
        "103.145.13.8", "172.17.1.115", "172.17.1.120", "10.212.1.254", "8.8.8.8",
    ]
    rng = random.Random(seed)
    out: List[Dict[str, Any]] = []
    for rule in rules:
        for _ in range(variations_per_rule):
            agent_id, agent_name = rng.choice(_AGENTS)
            raw = {
                "rule": {
                    "id": rule["rule_id"],
                    "level": rule["level"],
                    "description": rule["description"],
                    "groups": rule["groups"],
                    "mitre": {"id": rule["mitre_ids"], "tactic": []},
                    "firedtimes": rng.randint(1, 15),
                },
                "agent": {"id": agent_id, "name": agent_name},
                "data": {"srcip": rng.choice(_IPS), "dstip": rng.choice(_IPS)},
                "timestamp": None,
            }
            out.append({"raw": raw, "label": rule["label"]})
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extrait et labellise un sous-ensemble du ruleset officiel Wazuh.")
    parser.add_argument("--offline", action="store_true", help="Ne pas retélécharger, réutiliser le cache XML local (data/raw/wazuh_ruleset/).")
    args = parser.parse_args()

    from collections import Counter

    rules = build_ruleset_dataset(offline=args.offline)
    print(f"[fetch_wazuh_ruleset] {len(rules)} règles retenues (sur {len(RULE_FILES)} fichiers demandés).")
    print(f"[fetch_wazuh_ruleset] Répartition labels : {Counter(r['label'] for r in rules)}")
    print(f"[fetch_wazuh_ruleset] Répartition catégories : {Counter(r['category'] for r in rules)}")

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(rules, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[fetch_wazuh_ruleset] Écrit dans {OUTPUT_PATH}")
