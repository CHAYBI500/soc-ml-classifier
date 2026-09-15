"""
auth_db.py
==========
Couche d'accès à la petite base SQLite dédiée à l'authentification admin :
comptes, codes de vérification email, sessions, historique des connexions
(qui s'est connecté, avec quel email/nom, depuis quelle machine) et
anti-brute-force.

Séparée de tout accès au SQL Server surveillé (src/sql_monitor.py, lecture
seule sur l'infra cliente) : cette base est locale au service API, dédiée à
ses propres comptes admin.

Sécurité : TOUTES les requêtes ci-dessous utilisent des paramètres liés
("?") — aucune valeur utilisateur n'est jamais concaténée/formatée dans une
chaîne SQL — ce qui exclut par construction l'injection SQL sur ce module.

Fichier : data/auth.db (créé et migré automatiquement au premier import).
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

DB_PATH = Path("data/auth.db")

# sqlite3 gère mal les écritures concurrentes entre threads du threadpool FastAPI ;
# un verrou process-local sérialise les accès. Volume de trafic (login admin,
# quelques utilisateurs) largement compatible avec cette approche simple.
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_email_verified INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS email_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,             -- 'register' ou 'login'
    code_hash TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    ip TEXT,
    machine_name TEXT,
    user_agent TEXT
);

CREATE TABLE IF NOT EXISTS login_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER,
    email TEXT NOT NULL,
    name TEXT,
    ip TEXT,
    machine_name TEXT,
    user_agent TEXT,
    success INTEGER NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_throttle (
    throttle_key TEXT PRIMARY KEY,
    fail_count INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    last_attempt_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_history_email ON login_history(email);
CREATE INDEX IF NOT EXISTS idx_login_history_created ON login_history(created_at);
CREATE INDEX IF NOT EXISTS idx_email_codes_admin_purpose ON email_codes(admin_id, purpose);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
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


# --- Admins ------------------------------------------------------------------

def count_admins() -> int:
    with get_conn() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM admins").fetchone()
        return int(row["n"])


def create_admin(name: str, email: str, password_hash: str) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO admins (name, email, password_hash, is_email_verified, is_active, created_at) "
            "VALUES (?, ?, ?, 0, 1, ?)",
            (name, email.lower(), password_hash, now_iso()),
        )
        return int(cur.lastrowid)


def get_admin_by_email(email: str) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM admins WHERE email = ?", (email.lower(),)).fetchone()
        return dict(row) if row else None


def get_admin_by_id(admin_id: int) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM admins WHERE id = ?", (admin_id,)).fetchone()
        return dict(row) if row else None


def set_email_verified(admin_id: int) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE admins SET is_email_verified = 1 WHERE id = ?", (admin_id,))


def update_pending_admin(admin_id: int, name: str, password_hash: str) -> None:
    """Met à jour nom/mot de passe d'un compte PAS ENCORE vérifié qui retente une
    inscription (voir /auth/register) : un compte non vérifié n'est qu'une
    inscription en attente, pas un compte réellement pris — bloquer la
    ré-inscription dessus laisserait l'utilisateur définitivement coincé si le
    premier envoi d'email a échoué (ex: SMTP mal configuré)."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE admins SET name = ?, password_hash = ? WHERE id = ? AND is_email_verified = 0",
            (name, password_hash, admin_id),
        )


# --- Codes de vérification email (inscription + OTP de connexion) ------------

def create_email_code(admin_id: int, purpose: str, code_hash: str, ttl_minutes: int) -> int:
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO email_codes (admin_id, purpose, code_hash, attempts, expires_at, created_at) "
            "VALUES (?, ?, ?, 0, ?, ?)",
            (admin_id, purpose, code_hash, expires_at, now_iso()),
        )
        return int(cur.lastrowid)


def get_latest_active_code(admin_id: int, purpose: str) -> Optional[Dict[str, Any]]:
    """Dernier code non consommé pour cet admin/but (le plus récent), quel que
    soit son état d'expiration — c'est l'appelant qui vérifie expires_at, afin
    de pouvoir renvoyer un message clair ("code expiré" vs "code invalide")."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM email_codes WHERE admin_id = ? AND purpose = ? AND consumed_at IS NULL "
            "ORDER BY id DESC LIMIT 1",
            (admin_id, purpose),
        ).fetchone()
        return dict(row) if row else None


def increment_code_attempts(code_id: int) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE email_codes SET attempts = attempts + 1 WHERE id = ?", (code_id,))


def consume_code(code_id: int) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE email_codes SET consumed_at = ? WHERE id = ?", (now_iso(), code_id))


# --- Sessions ------------------------------------------------------------------

def create_session(
    admin_id: int, token_hash: str, ttl_hours: int, ip: Optional[str], machine_name: Optional[str], user_agent: Optional[str]
) -> int:
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO sessions (admin_id, token_hash, created_at, expires_at, ip, machine_name, user_agent) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (admin_id, token_hash, now_iso(), expires_at, ip, machine_name, user_agent),
        )
        return int(cur.lastrowid)


def get_active_session_by_token_hash(token_hash: str) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?",
            (token_hash, now_iso()),
        ).fetchone()
        return dict(row) if row else None


def revoke_session(token_hash: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
            (now_iso(), token_hash),
        )


# --- Historique de connexion (qui s'est connecté, depuis où) ------------------

def record_login_history(
    admin_id: Optional[int],
    email: str,
    name: Optional[str],
    ip: Optional[str],
    machine_name: Optional[str],
    user_agent: Optional[str],
    success: bool,
    reason: str,
) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO login_history (admin_id, email, name, ip, machine_name, user_agent, success, reason, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (admin_id, email.lower(), name, ip, machine_name, user_agent, 1 if success else 0, reason, now_iso()),
        )


def list_login_history(limit: int = 50) -> List[Dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, admin_id, email, name, ip, machine_name, user_agent, success, reason, created_at "
            "FROM login_history ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


# --- Anti brute-force ----------------------------------------------------------

def get_throttle(key: str) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM login_throttle WHERE throttle_key = ?", (key,)).fetchone()
        return dict(row) if row else None


def register_failed_attempt(key: str, lockout_threshold: int, lockout_minutes: int) -> None:
    with get_conn() as conn:
        row = conn.execute("SELECT fail_count FROM login_throttle WHERE throttle_key = ?", (key,)).fetchone()
        fail_count = (row["fail_count"] if row else 0) + 1
        locked_until = None
        if fail_count >= lockout_threshold:
            locked_until = (datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)).isoformat()
        conn.execute(
            "INSERT INTO login_throttle (throttle_key, fail_count, locked_until, last_attempt_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(throttle_key) DO UPDATE SET fail_count = ?, locked_until = ?, last_attempt_at = ?",
            (key, fail_count, locked_until, now_iso(), fail_count, locked_until, now_iso()),
        )


def reset_throttle(key: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM login_throttle WHERE throttle_key = ?", (key,))
