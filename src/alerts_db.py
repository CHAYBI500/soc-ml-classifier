"""
alerts_db.py
============
Persistance SQLite locale de deux journaux distincts :

1. critical_alerts : uniquement les alertes CRITIQUES (priority_label "Critique" ou
   "Élevée", voir src/api.py::_compute_priority) — journal d'audit / conformité,
   "qu'est-ce qui a réellement nécessité l'attention d'un analyste, et quand exactement".

2. alert_log + stats_totals : le flux GÉNÉRAL (toutes les alertes, logs bruts comme
   verdicts de classification) et les compteurs agrégés, pour que le dashboard reprenne
   là où il s'est arrêté après un redémarrage de l'API au lieu de repartir de zéro —
   src/api.py::on_startup recharge ces deux tables dans _alert_history / _stats au
   démarrage du process. Sans ça, l'historique en mémoire (deque, voir api.py) est perdu
   à chaque redémarrage, ce qui n'est pas acceptable pour un outil utilisé en continu par
   un SOC (on doit pouvoir redémarrer l'API — déploiement, crash, maintenance — sans que
   les logs et classifications déjà traités disparaissent de l'écran).

Même pattern que src/auth_db.py (SQLite, verrou process-local, requêtes paramétrées
"?" — aucune valeur ne transite jamais formatée dans une chaîne SQL) mais fichier
séparé : domaine différent (alertes de sécurité vs comptes admin), cycle de vie et
volume potentiellement différents.

Fichier : data/alerts.db (créé et migré automatiquement au premier appel de init_db()).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

DB_PATH = Path("data/alerts.db")

_lock = threading.Lock()

# Nombre maximum de lignes conservées dans alert_log (flux général) : borne la taille du
# fichier sur un SOC qui tourne en continu pendant des mois. Doit rester nettement au-dessus
# de HISTORY_MAXLEN côté api.py (500) pour laisser de la marge de rechargement au démarrage.
ALERT_LOG_MAXLEN = 3000
# Le trim (DELETE des lignes les plus anciennes au-delà de ALERT_LOG_MAXLEN) ne s'exécute
# qu'une fois tous les N appels à upsert_alert_log plutôt qu'à chaque appel : la requête de
# comptage/suppression a un coût, inutile de le payer sur chaque alerte alors que dépasser
# la limite de quelques dizaines de lignes entre deux trims est sans conséquence.
_TRIM_EVERY = 25
_write_count = 0

SCHEMA = """
CREATE TABLE IF NOT EXISTS critical_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL UNIQUE,      -- id stable de l'entrée (voir api.py::_classify)
    rule_id TEXT,
    rule_description TEXT,
    rule_level INTEGER,
    category TEXT,
    category_label TEXT,
    priority_score INTEGER,
    priority_label TEXT,
    prediction TEXT,
    confidence REAL,
    agent_name TEXT,
    srcip TEXT,
    dstip TEXT,
    rule_mitre_id TEXT,
    rule_mitre_tactic TEXT,
    is_chain_signal INTEGER NOT NULL DEFAULT 0,
    chain_categories TEXT,              -- CSV des catégories corrélées, voir _classify
    repeat_count INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'new', -- synchronisé depuis /alerts/{id}/status|suppress
    first_seen TEXT NOT NULL,           -- date/heure EXACTE de la première occurrence
    last_seen TEXT NOT NULL,            -- date/heure EXACTE de la dernière occurrence
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_critical_alerts_last_seen ON critical_alerts(last_seen);
CREATE INDEX IF NOT EXISTS idx_critical_alerts_agent ON critical_alerts(agent_name);
CREATE INDEX IF NOT EXISTS idx_critical_alerts_category ON critical_alerts(category);

-- Flux général (toutes les alertes, pas seulement les critiques) : reflet durable de
-- api.py::_alert_history, une ligne par (rule_id, agent_name) actif, mise à jour en place
-- en cas de répétition — même logique de regroupement que côté mémoire.
CREATE TABLE IF NOT EXISTS alert_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    rule_id TEXT,
    rule_description TEXT,
    rule_level INTEGER,
    rule_groups TEXT,
    category TEXT,
    category_label TEXT,
    category_confidence REAL,
    priority_score INTEGER,
    priority_label TEXT,
    prediction TEXT,
    confidence REAL,
    agent_name TEXT,
    srcip TEXT,
    dstip TEXT,
    rule_mitre_id TEXT,
    rule_mitre_tactic TEXT,
    is_chain_signal INTEGER NOT NULL DEFAULT 0,
    chain_categories TEXT,              -- JSON (liste), contrairement au CSV de critical_alerts
    repeat_count INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'new',
    should_notify INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alert_log_updated ON alert_log(updated_at);
CREATE INDEX IF NOT EXISTS idx_alert_log_agent ON alert_log(agent_name);

-- Compteurs agrégés (ligne unique id=1) : total/TP/FP/catégories affichés par /stats,
-- pour que ces chiffres continuent de progresser après un redémarrage au lieu de
-- retomber à 0.
CREATE TABLE IF NOT EXISTS stats_totals (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    total INTEGER NOT NULL DEFAULT 0,
    true_positive INTEGER NOT NULL DEFAULT 0,
    false_positive INTEGER NOT NULL DEFAULT 0,
    category_counts TEXT NOT NULL DEFAULT '{}',  -- JSON {slug: count}
    updated_at TEXT NOT NULL
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # WAL au lieu du rollback journal par défaut : un writer n'y bloque plus les lecteurs
    # (dashboard qui lirait la DB) et surtout réduit la contention entre les écritures
    # elles-mêmes — pertinent ici car _classify() (api.py) peut faire jusqu'à 3 écritures
    # (critical_alerts + alert_log + stats_totals) par alerte, toutes sous le même _lock
    # process-local. PRAGMA appliqué à chaque connexion : idempotent si déjà actif, et
    # met à niveau automatiquement une base data/alerts.db créée avant ce changement (le
    # mode WAL est persisté dans le fichier lui-même une fois activé). synchronous=NORMAL
    # est le pairing standard recommandé avec WAL : fsync moins agressif qu'en mode FULL,
    # toujours sûr contre un crash du process, seul un crash OS/coupure secteur combiné à
    # WAL pourrait faire perdre les toutes dernières transactions commitées — compromis
    # acceptable pour un journal d'alertes, pas pour une base financière.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    with _lock:
        conn = _connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def upsert_critical_alert(entry: Dict[str, Any]) -> None:
    """Insère l'alerte critique, ou met à jour la ligne existante (même alert_id) si elle
    se répète — cohérent avec la déduplication déjà faite en mémoire (voir
    api.py::_active_alert_groups) : un incident qui se répète reste UNE ligne, avec
    repeat_count/last_seen mis à jour, pas une ligne par occurrence."""
    now = now_iso()
    chain_categories = ",".join(entry.get("chain_categories") or [])
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO critical_alerts (
                alert_id, rule_id, rule_description, rule_level, category, category_label,
                priority_score, priority_label, prediction, confidence, agent_name, srcip, dstip,
                rule_mitre_id, rule_mitre_tactic, is_chain_signal, chain_categories, repeat_count,
                status, first_seen, last_seen, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(alert_id) DO UPDATE SET
                rule_level = excluded.rule_level,
                category = excluded.category,
                category_label = excluded.category_label,
                priority_score = excluded.priority_score,
                priority_label = excluded.priority_label,
                prediction = excluded.prediction,
                confidence = excluded.confidence,
                is_chain_signal = excluded.is_chain_signal,
                chain_categories = excluded.chain_categories,
                repeat_count = excluded.repeat_count,
                status = excluded.status,
                last_seen = excluded.last_seen,
                updated_at = excluded.updated_at
            """,
            (
                entry.get("id"),
                entry.get("rule_id"),
                entry.get("rule_description"),
                entry.get("rule_level"),
                entry.get("category"),
                entry.get("category_label"),
                entry.get("priority_score"),
                entry.get("priority_label"),
                entry.get("prediction"),
                entry.get("confidence"),
                entry.get("agent_name"),
                entry.get("srcip"),
                entry.get("dstip"),
                entry.get("rule_mitre_id"),
                entry.get("rule_mitre_tactic"),
                int(bool(entry.get("is_chain_signal"))),
                chain_categories,
                entry.get("repeat_count", 1),
                entry.get("status", "new"),
                entry.get("first_seen") or now,
                entry.get("last_seen") or now,
                now,
                now,
            ),
        )


def update_status(alert_id: str, status: str) -> None:
    """Synchronise un changement de statut (voir api.py::set_alert_status/suppress_alert)
    sur les DEUX journaux (critical_alerts + alert_log) — un alert_id donné n'existe que
    dans au plus une des deux tables (critical_alerts seulement si l'alerte a atteint une
    priorité Critique/Élevée un jour), donc l'UPDATE qui ne correspond à aucune ligne est
    un no-op silencieux, pas une erreur."""
    now = now_iso()
    with get_conn() as conn:
        conn.execute(
            "UPDATE critical_alerts SET status = ?, updated_at = ? WHERE alert_id = ?",
            (status, now, alert_id),
        )
        conn.execute(
            "UPDATE alert_log SET status = ?, updated_at = ? WHERE alert_id = ?",
            (status, now, alert_id),
        )


def upsert_alert_log(entry: Dict[str, Any]) -> None:
    """Persiste CHAQUE alerte traitée (pas seulement les critiques, voir upsert_critical_alert)
    dans le journal général, pour que api.py::on_startup puisse reconstruire _alert_history
    après un redémarrage. Même sémantique d'upsert que upsert_critical_alert : une répétition
    (même alert_id) met à jour la ligne existante plutôt que d'en créer une nouvelle."""
    global _write_count
    now = now_iso()
    chain_categories_json = json.dumps(entry.get("chain_categories") or [])
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO alert_log (
                alert_id, timestamp, rule_id, rule_description, rule_level, rule_groups,
                category, category_label, category_confidence, priority_score, priority_label,
                prediction, confidence, agent_name, srcip, dstip, rule_mitre_id, rule_mitre_tactic,
                is_chain_signal, chain_categories, repeat_count, status, should_notify,
                first_seen, last_seen, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(alert_id) DO UPDATE SET
                timestamp = excluded.timestamp,
                rule_level = excluded.rule_level,
                category = excluded.category,
                category_label = excluded.category_label,
                category_confidence = excluded.category_confidence,
                priority_score = excluded.priority_score,
                priority_label = excluded.priority_label,
                prediction = excluded.prediction,
                confidence = excluded.confidence,
                is_chain_signal = excluded.is_chain_signal,
                chain_categories = excluded.chain_categories,
                repeat_count = excluded.repeat_count,
                status = excluded.status,
                should_notify = excluded.should_notify,
                last_seen = excluded.last_seen,
                updated_at = excluded.updated_at
            """,
            (
                entry.get("id"),
                entry.get("timestamp") or now,
                entry.get("rule_id"),
                entry.get("rule_description"),
                entry.get("rule_level"),
                entry.get("rule_groups"),
                entry.get("category"),
                entry.get("category_label"),
                entry.get("category_confidence"),
                entry.get("priority_score"),
                entry.get("priority_label"),
                entry.get("prediction"),
                entry.get("confidence"),
                entry.get("agent_name"),
                entry.get("srcip"),
                entry.get("dstip"),
                entry.get("rule_mitre_id"),
                entry.get("rule_mitre_tactic"),
                int(bool(entry.get("is_chain_signal"))),
                chain_categories_json,
                entry.get("repeat_count", 1),
                entry.get("status", "new"),
                int(bool(entry.get("should_notify"))),
                entry.get("first_seen") or now,
                entry.get("last_seen") or now,
                now,
                now,
            ),
        )
        _write_count += 1
        if _write_count % _TRIM_EVERY == 0:
            conn.execute(
                "DELETE FROM alert_log WHERE id NOT IN "
                "(SELECT id FROM alert_log ORDER BY updated_at DESC LIMIT ?)",
                (ALERT_LOG_MAXLEN,),
            )


def list_recent_alert_log(limit: int = 500) -> List[Dict[str, Any]]:
    """Relit le flux général, plus récent en premier — utilisé une seule fois, au démarrage
    de l'API, pour repeupler _alert_history (voir api.py::on_startup)."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM alert_log ORDER BY updated_at DESC LIMIT ?", (limit,)
        ).fetchall()
    entries = []
    for row in rows:
        d = dict(row)
        try:
            chain_categories = json.loads(d.get("chain_categories") or "[]")
        except (TypeError, ValueError):
            chain_categories = []
        entries.append(
            {
                "id": d.get("alert_id"),
                "timestamp": d.get("timestamp"),
                "first_seen": d.get("first_seen"),
                "last_seen": d.get("last_seen"),
                "repeat_count": d.get("repeat_count", 1),
                "rule_id": d.get("rule_id"),
                "rule_description": d.get("rule_description"),
                "prediction": d.get("prediction"),
                "confidence": d.get("confidence"),
                "agent_name": d.get("agent_name"),
                "rule_level": d.get("rule_level"),
                "rule_groups": d.get("rule_groups"),
                "srcip": d.get("srcip"),
                "dstip": d.get("dstip"),
                "rule_mitre_id": d.get("rule_mitre_id"),
                "rule_mitre_tactic": d.get("rule_mitre_tactic"),
                "category": d.get("category"),
                "category_label": d.get("category_label"),
                "category_confidence": d.get("category_confidence"),
                "priority_score": d.get("priority_score"),
                "priority_label": d.get("priority_label"),
                "is_chain_signal": bool(d.get("is_chain_signal")),
                "chain_categories": chain_categories,
                "status": d.get("status", "new"),
                "should_notify": bool(d.get("should_notify")),
            }
        )
    return entries


def save_stats(total: int, true_positive: int, false_positive: int, category_counts: Dict[str, int]) -> None:
    """Persiste les compteurs agrégés (voir api.py::_stats) pour qu'ils continuent de
    progresser après un redémarrage au lieu de retomber à 0 — appelé à chaque alerte
    classifiée, comme upsert_alert_log."""
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO stats_totals (id, total, true_positive, false_positive, category_counts, updated_at)
            VALUES (1, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                total = excluded.total,
                true_positive = excluded.true_positive,
                false_positive = excluded.false_positive,
                category_counts = excluded.category_counts,
                updated_at = excluded.updated_at
            """,
            (total, true_positive, false_positive, json.dumps(category_counts), now_iso()),
        )


def load_stats() -> Optional[Dict[str, Any]]:
    """Relit les compteurs agrégés persistés, si présents (première exécution jamais lancée
    -> None, l'appelant garde alors les compteurs à 0 par défaut)."""
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM stats_totals WHERE id = 1").fetchone()
    if not row:
        return None
    d = dict(row)
    try:
        d["category_counts"] = json.loads(d.get("category_counts") or "{}")
    except (TypeError, ValueError):
        d["category_counts"] = {}
    return d


def list_critical_alerts(
    limit: int = 100,
    since: Optional[str] = None,
    until: Optional[str] = None,
    agent_name: Optional[str] = None,
    category: Optional[str] = None,
) -> List[Dict[str, Any]]:
    query = "SELECT * FROM critical_alerts WHERE 1=1"
    params: List[Any] = []
    if since:
        query += " AND last_seen >= ?"
        params.append(since)
    if until:
        query += " AND last_seen <= ?"
        params.append(until)
    if agent_name:
        query += " AND agent_name = ?"
        params.append(agent_name)
    if category:
        query += " AND category = ?"
        params.append(category)
    query += " ORDER BY last_seen DESC LIMIT ?"
    params.append(limit)

    with get_conn() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
