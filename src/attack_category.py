"""
attack_category.py
===================
Taxonomie de catégories d'attaque/incident et étiquetage heuristique (faible supervision)
à partir des métadonnées déjà présentes dans une alerte Wazuh parsée (rule.groups,
rule.description, MITRE, et le signal d'injection SQL calculé par feature_engineering).

Pourquoi une taxonomie heuristique plutôt qu'un dataset externe labellisé par catégorie ?
Aucun des datasets Wazuh/HIDS disponibles publiquement (voir README) ne fournit de label
"type d'attaque" par alerte — seulement TP/FP. On dérive donc la catégorie directement des
champs structurés que Wazuh fournit déjà sur CHAQUE alerte (groups, MITRE), ce qui reste
valable quelle que soit la source des alertes (dataset d'entraînement ou trafic Wazuh réel),
contrairement à un modèle entraîné sur un dataset externe à un schéma différent.

Utilisé à deux endroits :
    - convert_hf_dataset.py : génère la colonne "category" du CSV d'entraînement.
    - api.py                : calcule la catégorie à la volée pour chaque alerte /predict.

Le modèle multi-classe (train_category_model.py) apprend ensuite à reproduire/généraliser
cette catégorisation à partir des mêmes features que le modèle TP/FP (rule_level, groupes,
MITRE, signal SQLi...), ce qui lui permet de rester correct même quand rule.groups est
incomplet ou absent (cas fréquent selon la configuration du manager Wazuh).
"""

from __future__ import annotations

from typing import Any, Dict

from src.feature_engineering import _cve_signal, _sqli_signal

# slug -> métadonnées d'affichage (libellé FR, couleur = nom de variable CSS du dashboard,
# sans le préfixe "--"). "sql" utilise une couleur dédiée (voir dashboard) pour ressortir
# fortement, conformément à la demande de mise en avant des menaces SQL. "ddos" partage
# intentionnellement la couleur "tp" (même famille "sévérité/impact élevé" que malware :
# testé à la validation — aucune teinte chaude supplémentaire ne passe le seuil de
# distinction perceptuelle vis-à-vis de "tp"/"warn" déjà utilisées, voir dashboard). "vuln"
# est une couleur cyan dédiée, ajoutée et validée (contraste + distinction CVD) spécifiquement
# pour ne plus partager "warn" avec "bruteforce" — voir la variable CSS --vuln du dashboard.
# "weight" (0-1) = criticité utilisée par api.py::_compute_priority pour le score de
# priorité composite du flux — pas un signal ML, juste une pondération éditoriale de
# "à quel point cette catégorie mérite l'attention d'un analyste en premier".
CATEGORIES: Dict[str, Dict[str, Any]] = {
    "sql": {"label": "Injection SQL / Base de données", "color": "sql", "weight": 1.0},
    "malware": {"label": "Malware / Intégrité fichier", "color": "tp", "weight": 1.0},
    "bruteforce": {"label": "Brute force / Authentification", "color": "warn", "weight": 0.8},
    "ddos": {"label": "DDoS / Déni de service", "color": "tp", "weight": 0.9},
    "vulnerability": {"label": "Vulnérabilité / CVE", "color": "vuln", "weight": 0.6},
    "recon": {"label": "Reconnaissance / Scan réseau", "color": "ai", "weight": 0.5},
    "web": {"label": "Attaque Web (hors SQL)", "color": "accent", "weight": 0.6},
    "endpoint": {"label": "Windows / Endpoint", "color": "ok", "weight": 0.3},
    "network": {"label": "Réseau / Pare-feu", "color": "fp-text", "weight": 0.3},
    "other": {"label": "Autre / Non catégorisé", "color": "text-dim", "weight": 0.1},
    # Court-circuit avant le modèle ML pour les rule_id connus comme bruit opérationnel
    # (voir api.py::_NON_ACTIONABLE_RULE_IDS) — jamais prédite par le classifieur lui-même.
    "operational": {"label": "Bruit opérationnel / Technique", "color": "text-dim", "weight": 0.0},
}

# Ordre de priorité : le premier bloc qui matche l'emporte (une alerte "web" + "sql" doit
# être classée SQL, catégorie la plus actionnable/spécifique ici).
_SQL_GROUPS = {"sql_injection", "sqli", "mssql", "mysql", "postgresql", "database"}
_SQL_KEYWORDS = (
    "sql server", "mssql", "mysql", "postgres", "postgresql", "sql injection",
    "sp_password", "xp_cmdshell", "database",
)
_MALWARE_GROUPS = {"malware", "virustotal", "rootcheck"}
_MALWARE_MITRE_PREFIXES = ("T1204", "T1105", "T1055")
_MALWARE_KEYWORDS = ("malware", "trojan", "ransomware", "virus", "eicar")

_BRUTEFORCE_GROUPS = {"authentication_failed", "authentication_failures", "sshd"}
_BRUTEFORCE_MITRE_PREFIXES = ("T1110",)
_BRUTEFORCE_KEYWORDS = (
    "authentication fail", "logon failure", "invalid password", "brute force",
    "multiple authentication failures", "failed login", "login attempt",
)

# DDoS / déni de service : Wazuh n'a pas de groupe dédié standard, donc on s'appuie surtout
# sur des mots-clés de description (règles pare-feu/IDS/web personnalisées qui mentionnent
# explicitement un flood/déni de service) et sur MITRE T1498 (Network DoS) / T1499 (Endpoint
# DoS). Volontairement DISTINCT de "bruteforce" : un déni de service vise la disponibilité
# (volume de trafic), pas l'authentification (voir aussi distinct_srcip_5min dans
# feature_engineering.py, qui aide le modèle ML à séparer une rafale mono-IP — brute force —
# d'une rafale multi-IP — DDoS distribué).
_DDOS_GROUPS = {"ddos", "dos"}
_DDOS_MITRE_PREFIXES = ("T1498", "T1499")
_DDOS_KEYWORDS = (
    "ddos", "dos attack", "denial of service", "syn flood", "udp flood", "icmp flood",
    "http flood", "slowloris", "amplification attack", "connection flood",
    "excessive number of connections", "traffic flood",
)

# Vulnérabilité / CVE : module Wazuh "vulnerability-detector" (audit de paquets installés
# vs bases CVE), ou toute alerte mentionnant explicitement un identifiant CVE. Catégorie
# préventive (logiciel vulnérable détecté) plutôt qu'une attaque en cours.
_VULN_GROUPS = {"vulnerability-detector", "vuln"}
_VULN_KEYWORDS = (
    "vulnerability", "vulnerable package", "vulnerable software", "unpatched",
    "exploit available", "outdated version", "vulnérabilité",
)

_RECON_GROUPS = {"recon"}
# "scan" seul a été retiré (trop générique en sous-chaîne : matchait "rescan"/"full scan
# required" sur des alertes de diagnostic logiciel Windows Defender sans lien avec une
# reconnaissance réseau, découvert en minant le ruleset officiel Wazuh — voir
# src/fetch_wazuh_ruleset.py). Remplacé par des expressions plus spécifiques.
_RECON_KEYWORDS = (
    "nmap", "port scan", "network scan", "scanning attempt", "host discovery",
    "reconnaissance", "web server scan",
)

_WEB_GROUPS = {"web"}
# "attack" seul est volontairement exclu : c'est un groupe Wazuh générique qui apparaît sur
# des règles recon/firewall/brute-force aussi bien que web — l'utiliser ici masquerait ces
# autres catégories (ex: une règle firewall avec groups=["firewall","attack"] finirait à tort
# en "web" au lieu de "network"). On garde des mots-clés dédiés pour couvrir les cas web sans
# groupe "web" explicite.
_WEB_KEYWORDS = ("web attack", "xss", "cross-site", "rfi", "lfi", "command injection")

_ENDPOINT_GROUPS = {"windows", "powershell", "sysmon"}
_ENDPOINT_KEYWORDS = ("powershell", "sysmon", "wmi")

_NETWORK_GROUPS = {"firewall"}


def derive_category(record: Dict[str, Any]) -> str:
    """
    Retourne le slug de catégorie (clé de CATEGORIES) pour un enregistrement issu de
    parse_wazuh.parse_alert() (ou tout dict exposant les mêmes clés : rule_groups,
    rule_description, mitre_ids, mitre_tactics, text_blob).
    """
    groups = set(record.get("rule_groups") or [])
    description = str(record.get("rule_description") or "").lower()
    mitre_ids = list(record.get("mitre_ids") or [])
    mitre_tactics = [str(t).lower() for t in (record.get("mitre_tactics") or [])]
    text_blob = record.get("text_blob") or description

    def mitre_matches(prefixes: tuple) -> bool:
        return any(str(m).startswith(prefixes) for m in mitre_ids)

    has_sqli, _ = _sqli_signal(text_blob)
    has_cve, _ = _cve_signal(text_blob)

    # has_sqli seul est un signal texte faible (regex sur le text_blob complet, y compris
    # full_log/data.* — voir feature_engineering.py) : suffisant pour classer "sql" sauf si
    # l'alerte est déjà explicitement taguée Windows/endpoint par Wazuh (groups), auquel cas
    # on exige un signal fort (groupe SQL dédié ou mot-clé explicite) pour ne pas laisser un
    # hit regex isolé écraser une catégorie déjà certaine côté métadonnées structurées.
    strong_sql_signal = bool(groups & _SQL_GROUPS) or any(k in description for k in _SQL_KEYWORDS)
    if strong_sql_signal or (has_sqli and not (groups & _ENDPOINT_GROUPS)):
        return "sql"
    if (groups & _MALWARE_GROUPS) or mitre_matches(_MALWARE_MITRE_PREFIXES) or any(
        k in description for k in _MALWARE_KEYWORDS
    ):
        return "malware"
    if has_cve or (groups & _VULN_GROUPS) or any(k in description for k in _VULN_KEYWORDS):
        return "vulnerability"
    if (groups & _BRUTEFORCE_GROUPS) or mitre_matches(_BRUTEFORCE_MITRE_PREFIXES) or any(
        k in description for k in _BRUTEFORCE_KEYWORDS
    ):
        return "bruteforce"
    if (groups & _DDOS_GROUPS) or mitre_matches(_DDOS_MITRE_PREFIXES) or any(
        k in description for k in _DDOS_KEYWORDS
    ):
        return "ddos"
    if (groups & _RECON_GROUPS) or "reconnaissance" in mitre_tactics or any(
        k in description for k in _RECON_KEYWORDS
    ):
        return "recon"
    if (groups & _WEB_GROUPS) or any(k in description for k in _WEB_KEYWORDS):
        return "web"
    if (groups & _ENDPOINT_GROUPS) or any(k in description for k in _ENDPOINT_KEYWORDS):
        return "endpoint"
    if groups & _NETWORK_GROUPS:
        return "network"
    return "other"


def category_label(slug: str) -> str:
    return CATEGORIES.get(slug, CATEGORIES["other"])["label"]
