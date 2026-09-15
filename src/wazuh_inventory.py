"""
wazuh_inventory.py
===================
Connecteur vers l'API REST du manager Wazuh (port 55000 par défaut) pour l'onglet
"Hygiène IT" du dashboard : inventaire logiciel, ports ouverts, processus et correctifs
par agent (données syscollector), en complément des alertes de sécurité déjà couvertes par
le reste de l'API (qui ne voit que les événements, pas l'état/la posture des machines).

Ce n'est PAS un doublon du module "IT Hygiene" natif de Wazuh (Kibana/OpenSearch) : c'est
une vue légère et personnalisée embarquée dans CE dashboard, avec un score d'hygiène par
agent calculé ici (pas fourni nativement par Wazuh) pour prioriser visuellement les agents
les plus exposés — voir compute_hygiene_score() pour le détail, entièrement transparent
(pas de boîte noire) et volontairement simple (pas de base de vulnérabilités embarquée).

Configuration (variables d'environnement) :
    WAZUH_API_HOST        Hôte ou IP du manager Wazuh (ex: 10.212.2.170)
    WAZUH_API_PORT        Port de l'API REST Wazuh (défaut: 55000)
    WAZUH_API_USER        Utilisateur API Wazuh (lecture seule recommandé, voir ci-dessous)
    WAZUH_API_PASSWORD    Mot de passe
    WAZUH_API_VERIFY_SSL  "yes"/"no" (défaut: no — le manager utilise un certificat
                           auto-signé par défaut ; passe à "yes" si un certificat valide est en place)

Sécurité : créer un utilisateur API Wazuh dédié en lecture seule (RBAC) plutôt que d'utiliser
le compte admin par défaut — Wazuh Dashboard > Server management > Users & Roles, rôle avec
uniquement les permissions "agent:read" et "syscollector:read".

Dépendance : requests (déjà dans requirements.txt).
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

import requests

REQUEST_TIMEOUT_SECONDS = 8
TOKEN_TTL_SECONDS = 800  # un peu sous les 900s par défaut de Wazuh, marge de sécurité pour le cache

# Ports considérés sensibles s'ils sont exposés en LISTENING sur un agent -> pèsent sur le
# score d'hygiène (liste non exhaustive, volontairement centrée sur les services à fort impact
# s'ils sont accessibles sans contrôle : administration distante, bases de données, partage fichiers).
SENSITIVE_PORTS: Dict[int, str] = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 69: "TFTP", 111: "RPCbind", 135: "RPC",
    139: "NetBIOS", 161: "SNMP", 162: "SNMP-trap", 389: "LDAP", 445: "SMB",
    512: "rexec", 513: "rlogin", 514: "rsh", 1433: "MSSQL", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)", 6000: "X11", 6379: "Redis", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
}

# Marqueurs (sous-chaîne, insensible à la casse, cherchée dans "os.name + os.version") d'OS
# en fin de support connue -> signal de vulnérabilité fort (pas de correctifs de sécurité
# fournisseur possibles). Liste volontairement courte et statique (pas de flux CVE/EOL live),
# à réviser périodiquement — cohérent avec le reste du score, transparent et sans boîte noire.
_EOL_OS_MARKERS: List[tuple] = [
    ("windows xp", "Windows XP — fin de support Microsoft depuis avril 2014"),
    ("windows vista", "Windows Vista — fin de support Microsoft depuis avril 2017"),
    ("windows server 2003", "Windows Server 2003 — fin de support depuis juillet 2015"),
    ("windows server 2008", "Windows Server 2008 / 2008 R2 — fin de support depuis janvier 2020"),
    ("windows server 2012", "Windows Server 2012 / 2012 R2 — fin de support depuis octobre 2023"),
    ("windows 7", "Windows 7 — fin de support Microsoft depuis janvier 2020"),
    ("windows 8", "Windows 8 / 8.1 — fin de support Microsoft (2016 / janvier 2023)"),
    ("centos linux 6", "CentOS 6 — fin de support depuis novembre 2020"),
    ("centos linux 7", "CentOS 7 — fin de support depuis juin 2024"),
    ("centos linux 8", "CentOS 8 — fin de support anticipée depuis décembre 2021"),
    ("debian gnu/linux 8", "Debian 8 (Jessie) — fin de support depuis juin 2020"),
    ("debian gnu/linux 9", "Debian 9 (Stretch) — fin de support depuis juin 2022"),
    ("ubuntu 16.04", "Ubuntu 16.04 LTS — fin de support standard depuis avril 2021"),
    ("ubuntu 18.04", "Ubuntu 18.04 LTS — fin de support standard depuis mai 2023"),
]


class WazuhApiError(Exception):
    """Erreur de connexion, d'authentification ou de requête vers l'API REST Wazuh."""


_token_cache: Dict[str, Any] = {"token": None, "expires_at": 0.0}


def _base_url() -> str:
    host = os.environ.get("WAZUH_API_HOST")
    port = os.environ.get("WAZUH_API_PORT", "55000")
    if not host:
        raise WazuhApiError(
            "WAZUH_API_HOST non défini. Configure les variables WAZUH_API_* (voir l'en-tête "
            "de src/wazuh_inventory.py) dans ton .env."
        )
    return f"https://{host}:{port}"


def _verify_ssl() -> bool:
    return os.environ.get("WAZUH_API_VERIFY_SSL", "no").strip().lower() == "yes"


def _authenticate() -> str:
    user = os.environ.get("WAZUH_API_USER")
    password = os.environ.get("WAZUH_API_PASSWORD")
    if not user or not password:
        raise WazuhApiError("WAZUH_API_USER / WAZUH_API_PASSWORD non définis dans le .env.")

    try:
        res = requests.post(
            f"{_base_url()}/security/user/authenticate",
            auth=(user, password),
            verify=_verify_ssl(),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        res.raise_for_status()
    except requests.RequestException as exc:
        raise WazuhApiError(f"Authentification API Wazuh impossible : {exc}") from exc

    token = (res.json() or {}).get("data", {}).get("token")
    if not token:
        raise WazuhApiError("Réponse d'authentification Wazuh inattendue (pas de token dans la réponse).")
    return token


def _get_token(force_refresh: bool = False) -> str:
    now = time.time()
    if not force_refresh and _token_cache["token"] and now < _token_cache["expires_at"]:
        return _token_cache["token"]
    token = _authenticate()
    _token_cache["token"] = token
    _token_cache["expires_at"] = now + TOKEN_TTL_SECONDS
    return token


def _get(path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    token = _get_token()
    try:
        res = requests.get(
            f"{_base_url()}{path}",
            headers={"Authorization": f"Bearer {token}"},
            params=params,
            verify=_verify_ssl(),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if res.status_code == 401:
            # Token probablement expiré malgré le cache local -> on en force un nouveau et on
            # retente une seule fois avant d'abandonner.
            token = _get_token(force_refresh=True)
            res = requests.get(
                f"{_base_url()}{path}",
                headers={"Authorization": f"Bearer {token}"},
                params=params,
                verify=_verify_ssl(),
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        if not res.ok:
            # L'API Wazuh renvoie un JSON {"title","detail",...} bien plus utile que le texte
            # générique de raise_for_status() — on le remonte tel quel pour un vrai diagnostic.
            try:
                detail = res.json().get("detail") or res.text
            except ValueError:
                detail = res.text
            raise WazuhApiError(f"API Wazuh {res.status_code} sur {path} : {detail}")
        res.raise_for_status()
    except requests.RequestException as exc:
        raise WazuhApiError(f"Requête API Wazuh échouée ({path}) : {exc}") from exc
    return res.json()


def _affected_items(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    return ((payload or {}).get("data") or {}).get("affected_items") or []


def test_connection() -> Dict[str, Any]:
    """Vérifie la connectivité + authentification (utilisé par /hygiene/health)."""
    data = _get("/", params=None)
    info = (data or {}).get("data") or {}
    return {"connected": True, "title": info.get("title"), "api_version": info.get("api_version")}


def list_agents() -> List[Dict[str, Any]]:
    """Liste des agents Wazuh (hors manager lui-même, id=000)."""
    data = _get(
        "/agents",
        params={"select": "id,name,ip,status,os.platform,os.name,os.version,lastKeepAlive", "limit": 500},
    )
    return [a for a in _affected_items(data) if a.get("id") != "000"]


def get_packages(agent_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    data = _get(f"/syscollector/{agent_id}/packages", params={"limit": limit})
    return _affected_items(data)


def get_ports(agent_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    data = _get(f"/syscollector/{agent_id}/ports", params={"limit": limit})
    return _affected_items(data)


def get_processes(agent_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    data = _get(f"/syscollector/{agent_id}/processes", params={"limit": limit})
    return _affected_items(data)


def get_hotfixes(agent_id: str) -> List[Dict[str, Any]]:
    """Correctifs Windows (KB). Liste vide (pas d'erreur) pour un agent non-Windows."""
    try:
        data = _get(f"/syscollector/{agent_id}/hotfixes", params={"limit": 500})
        return _affected_items(data)
    except WazuhApiError:
        return []


def get_vulnerabilities(agent_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    """
    CVE corrélées par le module Vulnerability Detector de Wazuh (croisement du catalogue
    logiciel syscollector avec les flux CVE NVD/vendeurs, calculé côté manager — pas une
    base CVE embarquée ici). Contrairement à get_hotfixes(), NE PAS avaler WazuhApiError ici :
    l'appelant (src/api.py) doit pouvoir distinguer "module désactivé/indisponible sur ce
    manager" (fréquent selon les versions/licences Wazuh) de "aucune CVE trouvée" (liste
    vide légitime), ce que masquerait un retour [] silencieux dans les deux cas.
    """
    data = _get(f"/vulnerability/{agent_id}", params={"limit": limit})
    return _affected_items(data)


def _detect_eol_os(agent_os_name: str, agent_os_version: str) -> Optional[str]:
    """Retourne le message EOL si le nom/version d'OS matche un marqueur connu, sinon None."""
    haystack = f"{agent_os_name or ''} {agent_os_version or ''}".lower()
    for marker, message in _EOL_OS_MARKERS:
        if marker in haystack:
            return message
    return None


def compute_hygiene_score(
    agent_os_platform: str,
    ports: List[Dict[str, Any]],
    hotfixes: List[Dict[str, Any]],
    agent_os_name: str = "",
    agent_os_version: str = "",
    vulnerabilities: Optional[List[Dict[str, Any]]] = None,
    vulnerabilities_available: bool = False,
) -> Dict[str, Any]:
    """
    Score heuristique 0-100 (100 = meilleure hygiène apparente), calculé ici — PAS un score
    officiel Wazuh. Deux familles de signaux :

    1) Heuristique locale (toujours calculée, pas de dépendance à un module Wazuh optionnel) :
      - -10 points par port SENSIBLE distinct exposé en LISTENING (plafonné à -50)
      - -5 points par port LISTENING supplémentaire au-delà des 5 premiers, hors ports sensibles
        déjà comptés (surface d'exposition générale, plafonné à -20)
      - -15 points si agent Windows sans AUCUN correctif recensé par syscollector (signal faible :
        soit réellement pas de patch management, soit le scan syscollector des hotfixes est
        désactivé/n'a pas encore tourné — à vérifier manuellement, pas une certitude)
      - -25 points si l'OS de l'agent matche un marqueur de fin de support connu (_EOL_OS_MARKERS) :
        plus aucun correctif de sécurité fournisseur n'est possible, signal de vulnérabilité fort.

    2) CVE réelles (si le module Vulnerability Detector de Wazuh est actif côté manager, voir
       get_vulnerabilities()) — corrélation logiciel installé <-> flux CVE, pas une heuristique :
      - -8 points par CVE "critical" (plafonné à -40)
      - -4 points par CVE "high" (plafonné à -30)
      - -1 point par CVE "medium" (plafonné à -10)
      Les CVE "low"/"untriaged" sont recensées mais ne pèsent pas sur le score (bruit trop élevé).

    En plus du score, retourne "findings" : une liste de failles/vulnérabilités lisibles
    (severity/title/detail) pour répondre directement à la question "quelles sont les
    vulnérabilités de cet agent", pas seulement un chiffre agrégé — CVE réelles en tête (signal
    fort et nommé), puis constats heuristiques (ports/patchs/EOL).
    """
    listening = [p for p in ports if str(p.get("state", "")).lower() == "listening"]

    exposed_sensitive: List[Dict[str, Any]] = []
    seen_ports = set()
    for p in listening:
        local = p.get("local") or {}
        port_num = local.get("port")
        if port_num in SENSITIVE_PORTS and port_num not in seen_ports:
            seen_ports.add(port_num)
            exposed_sensitive.append({"port": port_num, "service": SENSITIVE_PORTS[port_num]})

    findings: List[Dict[str, str]] = []

    score = 100
    score -= min(len(exposed_sensitive) * 10, 50)
    for exposed in exposed_sensitive:
        findings.append(
            {
                "severity": "high",
                "title": f"Port {exposed['port']} ({exposed['service']}) exposé en écoute",
                "detail": (
                    f"Service à fort impact ({exposed['service']}) accessible sans contrôle "
                    "visible depuis ce dashboard si non filtré par pare-feu/segmentation réseau."
                ),
            }
        )

    extra_ports = max(len(listening) - 5, 0)
    score -= min(extra_ports * 5, 20)
    if extra_ports > 0:
        findings.append(
            {
                "severity": "low",
                "title": f"{extra_ports} port(s) supplémentaire(s) en écoute au-delà de 5",
                "detail": "Surface d'exposition réseau plus large que la moyenne observée sur ce parc.",
            }
        )

    no_patch_data = False
    if str(agent_os_platform or "").lower() == "windows" and not hotfixes:
        no_patch_data = True
        score -= 15
        findings.append(
            {
                "severity": "medium",
                "title": "Aucun correctif Windows recensé par syscollector",
                "detail": (
                    "Soit le patch management est réellement absent, soit le scan hotfixes "
                    "syscollector est désactivé ou n'a pas encore tourné — à vérifier manuellement."
                ),
            }
        )

    eol_message = _detect_eol_os(agent_os_name, agent_os_version)
    if eol_message:
        score -= 25
        findings.append(
            {
                "severity": "high",
                "title": "Système d'exploitation en fin de support",
                "detail": eol_message,
            }
        )

    # --- CVE réelles (Wazuh Vulnerability Detector), si le module a répondu pour cet agent ---
    vulnerabilities = vulnerabilities or []
    cve_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "untriaged": 0}
    for v in vulnerabilities:
        sev = str(v.get("severity") or "untriaged").strip().lower()
        if sev not in cve_counts:
            sev = "untriaged"
        cve_counts[sev] += 1

    score -= min(cve_counts["critical"] * 8, 40)
    score -= min(cve_counts["high"] * 4, 30)
    score -= min(cve_counts["medium"] * 1, 10)

    cve_findings: List[Dict[str, str]] = []
    # Un finding nommé par CVE critique/haute (les plus exploitables), triées par score CVSS
    # décroissant, plafonné à 8 pour ne pas noyer la liste — le détail complet reste consultable
    # dans l'onglet "CVE (Wazuh)" du détail agent côté dashboard.
    notable = sorted(
        (v for v in vulnerabilities if str(v.get("severity") or "").strip().lower() in ("critical", "high")),
        key=lambda v: float(v.get("cvss3_score") or v.get("cvss2_score") or 0),
        reverse=True,
    )[:8]
    for v in notable:
        cve_id = v.get("cve") or "CVE inconnue"
        pkg = v.get("name") or "paquet inconnu"
        pkg_version = v.get("version") or ""
        cvss = v.get("cvss3_score") or v.get("cvss2_score")
        sev_raw = str(v.get("severity") or "").strip().lower()
        cve_findings.append(
            {
                "severity": "high",
                "title": f"{cve_id} — {pkg} {pkg_version}".strip(),
                "detail": (
                    f"Sévérité Wazuh : {sev_raw or 'non triée'}"
                    + (f", CVSS {cvss}" if cvss else "")
                    + (f" — {v.get('title')}" if v.get("title") else "")
                ),
            }
        )
    remaining_medium_low = cve_counts["medium"] + cve_counts["low"] + cve_counts["untriaged"]
    if remaining_medium_low:
        cve_findings.append(
            {
                "severity": "medium" if cve_counts["medium"] else "low",
                "title": f"{remaining_medium_low} CVE supplémentaire(s) de sévérité moyenne/faible/non triée",
                "detail": f"{cve_counts['medium']} moyenne(s), {cve_counts['low']} faible(s), {cve_counts['untriaged']} non triée(s) — détail dans l'onglet CVE (Wazuh).",
            }
        )

    findings = cve_findings + findings
    findings.sort(key=lambda f: {"high": 0, "medium": 1, "low": 2}.get(f["severity"], 3))

    return {
        "score": max(score, 0),
        "listening_ports_count": len(listening),
        "exposed_sensitive_ports": exposed_sensitive,
        "no_patch_data": no_patch_data,
        "eol_os": eol_message,
        "findings": findings,
        "cve_counts": cve_counts,
        "cve_total": sum(cve_counts.values()),
        "cve_data_available": vulnerabilities_available,
    }
