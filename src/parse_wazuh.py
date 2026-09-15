"""
parse_wazuh.py
==============
Parse des alertes brutes Wazuh (JSON simple, JSON array, ou JSONL /var/ossec/logs/alerts/alerts.json)
et extraction des champs utiles pour le pipeline ML.

Champs extraits par alerte :
    rule.id, rule.level, rule.description, rule.groups, rule.mitre.id, rule.mitre.tactic,
    rule.firedtimes, agent.id, agent.name, data.srcip, data.dstip, timestamp

Utilisable en CLI :
    python -m src.parse_wazuh data/raw/alerts.json data/processed/parsed_alerts.jsonl

Ou en import :
    from src.parse_wazuh import parse_alert, parse_file
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


def _safe_get(d: Dict[str, Any], path: str, default=None):
    """Accès sûr à un champ imbriqué en dot-notation, ex: 'rule.mitre.id'."""
    cur: Any = d
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def parse_alert(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Transforme une alerte Wazuh brute (dict) en enregistrement plat exploitable.
    Retourne None si l'alerte n'a pas de rule.id exploitable (alerte malformée).
    """
    rule_id = _safe_get(raw, "rule.id")
    if rule_id is None:
        return None

    mitre_ids = _safe_get(raw, "rule.mitre.id", []) or []
    mitre_tactics = _safe_get(raw, "rule.mitre.tactic", []) or []
    groups = _safe_get(raw, "rule.groups", []) or []

    full_log = _safe_get(raw, "full_log")
    data_obj = _safe_get(raw, "data") or {}

    # Texte concaténé (description + full_log + valeurs du bloc "data") utilisé par le
    # feature engineering pour la détection par motif (ex: signatures d'injection SQL) —
    # c'est souvent dans full_log / data.* (requête, URL, payload) que la charge utile
    # d'une attaque apparaît, pas dans rule.description qui reste générique.
    data_values = " ".join(str(v) for v in data_obj.values() if v) if isinstance(data_obj, dict) else ""
    text_blob = " ".join(
        part for part in [
            str(_safe_get(raw, "rule.description", "") or ""),
            str(full_log or ""),
            data_values,
        ] if part
    )

    record = {
        "rule_id": str(rule_id),
        "rule_level": int(_safe_get(raw, "rule.level", 0) or 0),
        "rule_description": str(_safe_get(raw, "rule.description", "") or ""),
        "rule_groups": list(groups) if isinstance(groups, list) else [str(groups)],
        "rule_firedtimes": int(_safe_get(raw, "rule.firedtimes", 1) or 1),
        "mitre_ids": list(mitre_ids) if isinstance(mitre_ids, list) else [str(mitre_ids)],
        "mitre_tactics": list(mitre_tactics) if isinstance(mitre_tactics, list) else [str(mitre_tactics)],
        "agent_id": str(_safe_get(raw, "agent.id", "000") or "000"),
        "agent_name": str(_safe_get(raw, "agent.name", "unknown") or "unknown"),
        "srcip": _safe_get(raw, "data.srcip"),
        "dstip": _safe_get(raw, "data.dstip"),
        "timestamp": _safe_get(raw, "timestamp") or _safe_get(raw, "@timestamp"),
        "text_blob": text_blob,
        # on garde une copie de l'alerte brute pour le feature engineering avancé
        "_raw": raw,
    }
    return record


def _iter_raw_alerts(path: Path) -> Iterator[Dict[str, Any]]:
    """
    Itère sur des alertes Wazuh depuis un fichier qui peut être :
      - un JSON array : [ {...}, {...} ]
      - du JSONL (un objet JSON par ligne, format natif alerts.json de Wazuh)
      - un objet JSON unique { ... }
    """
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return

    # Cas 1: JSON array classique
    if text.startswith("["):
        try:
            data = json.loads(text)
            for item in data:
                if isinstance(item, dict):
                    yield item
            return
        except json.JSONDecodeError:
            pass  # on retombe sur le parsing ligne par ligne

    # Cas 2/3: JSONL (une alerte par ligne) ou objet unique
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                yield obj
        except json.JSONDecodeError:
            continue


def parse_file(input_path: str, output_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Parse un fichier d'alertes Wazuh brutes et retourne la liste des enregistrements plats.
    Si output_path est fourni, écrit le résultat en JSONL (sans le champ _raw, trop volumineux).
    """
    src = Path(input_path)
    if not src.exists():
        raise FileNotFoundError(f"Fichier introuvable : {input_path}")

    records = []
    skipped = 0
    for raw in _iter_raw_alerts(src):
        rec = parse_alert(raw)
        if rec is None:
            skipped += 1
            continue
        records.append(rec)

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as f:
            for rec in records:
                slim = {k: v for k, v in rec.items() if k != "_raw"}
                f.write(json.dumps(slim, ensure_ascii=False) + "\n")

    print(f"[parse_wazuh] {len(records)} alertes parsées, {skipped} ignorées (rule.id manquant).")
    return records


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m src.parse_wazuh <input.json> [output.jsonl]")
        sys.exit(1)

    inp = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else None
    parse_file(inp, out)
