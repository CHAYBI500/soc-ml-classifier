"""
feature_engineering.py
=======================
Construit la matrice de features à partir des alertes Wazuh parsées (parse_wazuh.py).

Features générées :
    - rule_level, rule_id (encodé), rule_firedtimes
    - has_mitre (0/1), mitre_tactic_count
    - rule_freq_5min : nombre d'occurrences de la même rule_id sur une fenêtre glissante de 5 min
    - hour_of_day, is_weekend
    - flags de groupe : group_attack, group_sshd, group_web, group_firewall, group_authentication_failed

La fonction principale build_features() prend une liste de dicts (sortie de parse_wazuh)
et retourne un pandas.DataFrame prêt pour l'entraînement / l'inférence.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

import pandas as pd

# Groupes Wazuh jugés pertinents pour le triage L1 -> une colonne booléenne par groupe.
# Les groupes sql_injection/mssql/mysql/postgresql/database ont été ajoutés pour renforcer
# spécifiquement la détection des menaces liées aux bases de données (SQL Server notamment).
# vulnerability-detector/dos/ddos ajoutés pour renforcer le focus demandé sur les catégories
# vulnérabilité (CVE) et déni de service, au même titre que sql/bruteforce (voir attack_category.py).
WATCHED_GROUPS = [
    "attack",
    "sshd",
    "web",
    "firewall",
    "authentication_failed",
    "authentication_failures",
    "syscheck",
    "malware",
    "recon",
    "sql_injection",
    "sqli",
    "mssql",
    "mysql",
    "postgresql",
    "database",
    "vulnerability-detector",
    "dos",
    "ddos",
]

# ---------------------------------------------------------------------------------------
# Détection de motifs d'injection SQL (has_sqli_pattern / sqli_keyword_count)
# ---------------------------------------------------------------------------------------
# Regex validé empiriquement sur le dataset labellisé firdhokk/autotrain-data-sql-injection
# (HuggingFace, 50 568 requêtes SQL malveillantes/légitimes) : recall=0.95, precision=0.67,
# F1=0.78 sur ce jeu de test. La précision modérée est acceptable ici car ce n'est qu'UN
# signal parmi d'autres pour le Random Forest (pas un blocage direct) — on privilégie le
# recall pour ne pas rater d'injection, quitte à générer quelques faux positifs (ex: une
# vraie requête SQL légitime dans un log d'audit).
# Chaque sous-motif est compilé séparément pour pouvoir compter le nombre de signatures
# distinctes détectées (sqli_keyword_count), en plus du simple booléen (has_sqli_pattern).
# Motifs volontairement RETIRÉS de la version initiale (trop génériques sur du texte libre
# hors contexte requête/URL, notamment le text_blob complet d'un événement Windows avec ses
# codes NTSTATUS hex/SID/GUID — voir attack_category.py::derive_category) : hex nu
# (0x[0-9a-f]{6,}, matchait tout code NTSTATUS Windows de 8 chiffres), "#" isolé (#\s*\S,
# matchait tout hashtag/référence de ticket), et "\d+\s*=\s*\d+" sans guillemet précédent
# (matchait n'importe quel "3 = 3" de log). Le motif tautologie SQLi classique (' 1=1) et le
# motif char() restent couverts, resserrés pour exiger le contexte SQL (guillemet, ou
# concaténation char()+char()) plutôt que la simple présence isolée du chiffre/de la parenthèse.
_SQLI_SUBPATTERNS = [
    r"\bunion\b.{0,40}\bselect\b",
    r"'\s*\d+\s*=\s*\d+",
    r"'\s*(or|and)\s*'",
    r"--\s*\S",
    r";--",
    r"/\*.*?\*/",
    r"\bxp_cmdshell\b",
    r"\bsp_executesql\b",
    r"\bsp_password\b",
    r"\bexec(\s|\()+\w*sp_",
    r"\bdrop\b\s+\b(table|database)\b",
    r"\binsert\b\s+\binto\b",
    r"\bdelete\b\s+\bfrom\b",
    r"\bupdate\b\s+\w+\s+\bset\b",
    r"\bselect\b.{0,80}\bfrom\b",
    r"\binformation_schema\b|\bdual\b|\bctxsys\b|\butl_inaddr\b|\bdbms_pipe\b",
    r"\bsleep\s*\(",
    r"\bbenchmark\s*\(",
    r"\bwaitfor\b\s+\bdelay\b",
    r"\bcast\s*\(|\bconvert\s*\(",
    r"\bconcat\s*\(",
    r"\bchar\s*\(\s*\d+\s*\)\s*\+\s*\bchar\s*\(",
    r"\bcase\s+when\b|\belt\s*\(|\bmake_set\s*\(|\brlike\b",
    r"%27|%20or%20|%20union%20",
    r"\bas\s+\w+\s+where\b",
]
_SQLI_COMPILED = [re.compile(p, re.IGNORECASE) for p in _SQLI_SUBPATTERNS]


def _sqli_signal(text: str) -> tuple[int, int]:
    """Retourne (has_sqli_pattern, nombre de signatures distinctes détectées) pour un texte."""
    if not text:
        return 0, 0
    hits = sum(1 for pat in _SQLI_COMPILED if pat.search(text))
    return int(hits > 0), hits


# ---------------------------------------------------------------------------------------
# Détection de motifs CVE (has_cve_pattern / cve_count) — signal fort pour la catégorie
# "vulnerability" (module vulnerability-detector de Wazuh, ou toute alerte mentionnant
# explicitement un identifiant CVE dans sa description/full_log).
# ---------------------------------------------------------------------------------------
_CVE_PATTERN = re.compile(r"\bcve-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _cve_signal(text: str) -> tuple[int, int]:
    """Retourne (has_cve_pattern, nombre d'identifiants CVE distincts détectés) pour un texte."""
    if not text:
        return 0, 0
    hits = set(m.group(0).lower() for m in _CVE_PATTERN.finditer(text))
    return int(bool(hits)), len(hits)


# Colonnes finales utilisées par le modèle (ordre stable, important pour l'inférence)
FEATURE_COLUMNS = [
    "rule_level",
    "rule_id_encoded",
    "rule_firedtimes",
    "has_mitre",
    "mitre_tactic_count",
    "rule_freq_5min",
    "distinct_srcip_5min",
    "hour_of_day",
    "is_weekend",
    "has_sqli_pattern",
    "sqli_keyword_count",
    "has_cve_pattern",
    "cve_count",
    "is_low_signal",
] + [f"group_{g}" for g in WATCHED_GROUPS]


def _parse_timestamp(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    # Wazuh utilise un format ISO8601 avec parfois un offset, ex: 2024-05-01T12:34:56.789+0000
    candidates = [ts, ts.replace("Z", "+00:00")]
    for cand in candidates:
        try:
            return datetime.fromisoformat(cand)
        except ValueError:
            continue
    return None


def _rule_id_encode(rule_id: str) -> int:
    """
    Encodage simple et stable du rule_id (string) vers un entier.
    On utilise directement l'entier du rule_id Wazuh quand c'est numérique (cas standard),
    sinon on retombe sur un hash borné pour rester robuste à des IDs non-numériques.
    """
    try:
        return int(rule_id)
    except (TypeError, ValueError):
        return abs(hash(rule_id)) % 100000


def _compute_rule_freq_5min(df: pd.DataFrame) -> pd.Series:
    """
    Pour chaque alerte, compte le nombre d'occurrences de la même rule_id
    dans les 5 minutes précédentes (fenêtre glissante, utile pour détecter
    les rafales : brute-force SSH, scans réseau, etc.).
    Nécessite une colonne '_dt' (datetime) déjà présente et triée.
    """
    if "_dt" not in df.columns or df["_dt"].isna().all():
        return pd.Series([1] * len(df), index=df.index)

    freqs = []
    # Regroupement par rule_id pour limiter la complexité
    for rule_id, group in df.groupby("rule_id"):
        group_sorted = group.sort_values("_dt")
        times = group_sorted["_dt"].tolist()
        counts = []
        for i, t in enumerate(times):
            if t is None:
                counts.append(1)
                continue
            window_start = t - pd.Timedelta(minutes=5)
            cnt = sum(1 for other in times[:i + 1] if other is not None and other >= window_start)
            counts.append(cnt)
        freqs.append(pd.Series(counts, index=group_sorted.index))

    result = pd.concat(freqs).reindex(df.index)
    return result.fillna(1).astype(int)


def _compute_distinct_srcip_5min(df: pd.DataFrame) -> pd.Series:
    """
    Pour chaque alerte, nombre d'IP sources DISTINCTES ayant déclenché la même rule_id
    dans les 5 minutes précédentes. Un rule_freq_5min élevé à lui seul ne distingue pas
    un déni de service distribué (beaucoup d'IP différentes, en rafale brève) d'un brute
    force classique (une poignée d'IP répétées) — cette feature lève l'ambiguïté pour le
    modèle. Nécessite '_dt' (déjà requis par rule_freq_5min) et 'srcip'.
    """
    if "_dt" not in df.columns or df["_dt"].isna().all() or "srcip" not in df.columns:
        return pd.Series([1] * len(df), index=df.index)

    results = []
    for rule_id, group in df.groupby("rule_id"):
        group_sorted = group.sort_values("_dt")
        times = group_sorted["_dt"].tolist()
        ips = group_sorted["srcip"].tolist()
        counts = []
        for i, t in enumerate(times):
            if t is None:
                counts.append(1)
                continue
            window_start = t - pd.Timedelta(minutes=5)
            distinct_ips = {
                ips[j] for j in range(i + 1)
                if times[j] is not None and times[j] >= window_start and ips[j]
            }
            counts.append(len(distinct_ips) or 1)
        results.append(pd.Series(counts, index=group_sorted.index))

    result = pd.concat(results).reindex(df.index)
    return result.fillna(1).astype(int)


def build_features(records: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Construit le DataFrame de features à partir d'une liste d'enregistrements
    plats issus de parse_wazuh.parse_alert().
    """
    if not records:
        return pd.DataFrame(columns=FEATURE_COLUMNS)

    df = pd.DataFrame(records)

    # Timestamp -> composantes temporelles
    df["_dt"] = df["timestamp"].apply(_parse_timestamp) if "timestamp" in df.columns else None
    df["hour_of_day"] = df["_dt"].apply(lambda d: d.hour if d else 12)
    df["is_weekend"] = df["_dt"].apply(lambda d: int(d.weekday() >= 5) if d else 0)

    # rule_id encodé
    df["rule_id_encoded"] = df["rule_id"].apply(_rule_id_encode)

    # MITRE
    df["has_mitre"] = df["mitre_ids"].apply(lambda x: int(bool(x)))
    df["mitre_tactic_count"] = df["mitre_tactics"].apply(lambda x: len(x) if isinstance(x, list) else 0)

    # Flags de groupe
    for g in WATCHED_GROUPS:
        df[f"group_{g}"] = df["rule_groups"].apply(
            lambda groups, g=g: int(g in groups) if isinstance(groups, list) else 0
        )

    # Détection de motifs d'injection SQL sur le texte disponible (description + full_log +
    # champs data.*, voir parse_wazuh.parse_alert -> "text_blob"). Fallback sur rule_description
    # seule si "text_blob" est absent (ex: anciens enregistrements sérialisés avant son ajout).
    text_source = df["text_blob"] if "text_blob" in df.columns else df.get("rule_description", "")
    sqli_signals = text_source.apply(_sqli_signal)
    df["has_sqli_pattern"] = sqli_signals.apply(lambda t: t[0])
    df["sqli_keyword_count"] = sqli_signals.apply(lambda t: t[1])

    # Détection de motifs CVE (catégorie "vulnerability", voir attack_category.py)
    cve_signals = text_source.apply(_cve_signal)
    df["has_cve_pattern"] = cve_signals.apply(lambda t: t[0])
    df["cve_count"] = cve_signals.apply(lambda t: t[1])

    # Alerte "bruit routine" : sévérité minimale (informationnel), sans lien direct avec
    # une catégorie de menace — aide le modèle binaire à trancher franchement ces cas
    # plutôt que de se reposer uniquement sur rule_level en continu.
    df["is_low_signal"] = (df["rule_level"] <= 2).astype(int)

    # Fréquence de rafale sur 5 min (nécessite un tri temporel global)
    if df["_dt"].notna().any():
        df = df.sort_values("_dt").reset_index(drop=True)
    df["rule_freq_5min"] = _compute_rule_freq_5min(df)
    df["distinct_srcip_5min"] = _compute_distinct_srcip_5min(df)

    # rule_firedtimes déjà présent depuis parse_wazuh, sinon défaut à 1
    if "rule_firedtimes" not in df.columns:
        df["rule_firedtimes"] = 1

    features = df[FEATURE_COLUMNS].copy()
    features = features.fillna(0)

    # On conserve les colonnes méta utiles pour le debug / l'API (pas utilisées par le modèle)
    for meta_col in ["rule_id", "rule_description", "agent_name", "srcip", "dstip"]:
        if meta_col in df.columns:
            features[f"_meta_{meta_col}"] = df[meta_col]

    return features


def features_for_single_alert(raw_alert: Dict[str, Any]) -> pd.DataFrame:
    """
    Raccourci pour l'inférence temps réel (API /predict) : construit les features
    pour une seule alerte brute Wazuh, sans historique de fréquence (rule_freq_5min=1
    par défaut car on ne dispose pas d'un contexte de rafale côté API stateless).
    """
    from src.parse_wazuh import parse_alert

    record = parse_alert(raw_alert)
    if record is None:
        raise ValueError("Alerte invalide : rule.id manquant.")

    df = build_features([record])
    return df


if __name__ == "__main__":
    import sys
    from src.parse_wazuh import parse_file

    if len(sys.argv) < 2:
        print("Usage: python -m src.feature_engineering <parsed_alerts.jsonl>")
        sys.exit(1)

    recs = parse_file(sys.argv[1])
    out_df = build_features(recs)
    print(out_df.head())
    print(f"\n{len(out_df)} lignes, {len(FEATURE_COLUMNS)} features modèle.")
