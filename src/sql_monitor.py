"""
sql_monitor.py
==============
Connecteur de surveillance en direct pour le SQL Server 2016 hébergé sur la VM
Windows Server 2019 (agent Wazuh existant). Interroge les DMV (Dynamic Management
Views) de SQL Server pour exposer : connexions actives, utilisateurs actifs,
permissions et appartenances aux rôles serveur.

Ce module NE remplace PAS le pipeline Wazuh (rules/décodeurs) : il apporte une vue
"état actuel" en direct, complémentaire aux alertes historiques déjà collectées
par l'agent (échecs d'authentification, etc.), que l'API expose séparément via
/sql/security-events (filtrage de l'historique d'alertes déjà en mémoire).

Configuration (variables d'environnement) :
    SQLSRV_HOST                 Hôte ou IP du SQL Server (ex: 172.17.1.115)
    SQLSRV_PORT                 Port TCP (défaut: 1433)
    SQLSRV_DATABASE             Base de connexion initiale (défaut: master)
    SQLSRV_TRUSTED_CONNECTION   "yes" pour auth Windows intégrée, sinon SQL auth (défaut: no)
    SQLSRV_USER                 Login SQL (si SQLSRV_TRUSTED_CONNECTION != yes)
    SQLSRV_PASSWORD             Mot de passe du login SQL
    SQLSRV_DRIVER               Nom du driver ODBC (défaut: "ODBC Driver 17 for SQL Server")
    SQLSRV_WAZUH_AGENT_NAME     Nom exact de l'agent Wazuh de cette VM, pour filtrer
                                 /sql/security-events (sinon filtrage par sous-chaîne "sql")

Sécurité : créer un login SQL dédié, en lecture seule, pour ce monitoring :

    CREATE LOGIN soc_monitor WITH PASSWORD = 'change_moi_' + CONVERT(varchar(36), NEWID());
    GRANT VIEW SERVER STATE TO soc_monitor;
    GRANT VIEW ANY DEFINITION TO soc_monitor;

Ne jamais utiliser un compte sysadmin/sa pour cette API.

Dépendance :
    pip install pyodbc
    (+ driver ODBC "ODBC Driver 17 for SQL Server" installé sur la machine qui exécute l'API)
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

CONNECT_TIMEOUT_SECONDS = 5
QUERY_TIMEOUT_SECONDS = 8


class SqlMonitorError(Exception):
    """Erreur de connexion ou de requête vers le SQL Server surveillé."""


def _build_connection_string() -> str:
    driver = os.environ.get("SQLSRV_DRIVER", "ODBC Driver 17 for SQL Server")
    host = os.environ.get("SQLSRV_HOST")
    port = os.environ.get("SQLSRV_PORT", "1433")
    database = os.environ.get("SQLSRV_DATABASE", "master")
    trusted = os.environ.get("SQLSRV_TRUSTED_CONNECTION", "no").strip().lower() == "yes"

    if not host:
        raise SqlMonitorError(
            "SQLSRV_HOST non défini. Configure les variables d'environnement SQLSRV_* "
            "(voir l'en-tête de src/sql_monitor.py)."
        )

    parts = [
        f"DRIVER={{{driver}}}",
        f"SERVER={host},{port}",
        f"DATABASE={database}",
        f"Connection Timeout={CONNECT_TIMEOUT_SECONDS}",
        "Encrypt=yes",
        "TrustServerCertificate=yes",
    ]

    if trusted:
        parts.append("Trusted_Connection=yes")
    else:
        user = os.environ.get("SQLSRV_USER")
        password = os.environ.get("SQLSRV_PASSWORD")
        if not user or not password:
            raise SqlMonitorError(
                "SQLSRV_USER / SQLSRV_PASSWORD non définis (ou SQLSRV_TRUSTED_CONNECTION=yes "
                "pour utiliser l'authentification Windows intégrée à la place)."
            )
        parts.append(f"UID={user}")
        parts.append(f"PWD={password}")

    return ";".join(parts)


def _get_connection():
    try:
        import pyodbc
    except ImportError as exc:
        raise SqlMonitorError(
            "Package pyodbc manquant. Installe-le avec `pip install pyodbc` et vérifie qu'un "
            "driver ODBC SQL Server est installé sur cette machine."
        ) from exc

    conn_str = _build_connection_string()
    try:
        conn = pyodbc.connect(conn_str, timeout=CONNECT_TIMEOUT_SECONDS)
    except pyodbc.Error as exc:
        raise SqlMonitorError(f"Connexion SQL Server impossible : {exc}") from exc
    conn.timeout = QUERY_TIMEOUT_SECONDS
    return conn


def _rows_to_dicts(cursor) -> List[Dict[str, Any]]:
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def _execute_query(conn, query: str) -> List[Dict[str, Any]]:
    """Exécute une requête et convertit le résultat, en traduisant toute erreur pyodbc
    (permission refusée, timeout, requête invalide...) en SqlMonitorError propre plutôt
    que de laisser remonter une exception brute (500 générique côté API)."""
    import pyodbc

    try:
        cursor = conn.cursor()
        cursor.execute(query)
        return _rows_to_dicts(cursor)
    except pyodbc.Error as exc:
        raise SqlMonitorError(f"Requête SQL Server échouée : {exc}") from exc


def test_connection() -> Dict[str, Any]:
    """Vérifie la connectivité et remonte la version du serveur (utilisé par /sql/health)."""
    import pyodbc

    conn = _get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT @@VERSION AS version, @@SERVERNAME AS server_name")
        row = cursor.fetchone()
        return {"connected": True, "server_name": row.server_name, "version": row.version.split("\n")[0]}
    except pyodbc.Error as exc:
        raise SqlMonitorError(f"Requête SQL Server échouée : {exc}") from exc
    finally:
        conn.close()


def get_active_sessions() -> List[Dict[str, Any]]:
    """Sessions/connexions utilisateur actives (sys.dm_exec_sessions + sys.dm_exec_connections)."""
    query = """
        SELECT
            s.session_id,
            s.login_name,
            s.host_name,
            s.program_name,
            s.status,
            DB_NAME(s.database_id) AS database_name,
            s.login_time,
            s.last_request_start_time,
            s.last_request_end_time,
            s.cpu_time,
            s.memory_usage,
            s.reads,
            s.writes,
            s.row_count,
            c.client_net_address,
            c.connect_time,
            c.net_transport,
            c.auth_scheme
        FROM sys.dm_exec_sessions s
        LEFT JOIN sys.dm_exec_connections c ON s.session_id = c.session_id
        WHERE s.is_user_process = 1
        ORDER BY s.login_time DESC
    """
    conn = _get_connection()
    try:
        return _execute_query(conn, query)
    finally:
        conn.close()


def get_active_users_summary(sessions: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Agrège les sessions actives par login : nombre de sessions, hôtes distincts, plus ancienne connexion."""
    if sessions is None:
        sessions = get_active_sessions()

    by_login: Dict[str, Dict[str, Any]] = {}
    for s in sessions:
        login = s.get("login_name") or "unknown"
        entry = by_login.setdefault(
            login,
            {"login_name": login, "session_count": 0, "hosts": set(), "programs": set(), "databases": set(), "first_login_time": None},
        )
        entry["session_count"] += 1
        if s.get("host_name"):
            entry["hosts"].add(s["host_name"])
        if s.get("program_name"):
            entry["programs"].add(s["program_name"])
        if s.get("database_name"):
            entry["databases"].add(s["database_name"])
        lt = s.get("login_time")
        if lt and (entry["first_login_time"] is None or lt < entry["first_login_time"]):
            entry["first_login_time"] = lt

    result = []
    for entry in by_login.values():
        result.append(
            {
                "login_name": entry["login_name"],
                "session_count": entry["session_count"],
                "hosts": sorted(entry["hosts"]),
                "programs": sorted(entry["programs"]),
                "databases": sorted(entry["databases"]),
                "first_login_time": entry["first_login_time"],
            }
        )
    result.sort(key=lambda e: e["session_count"], reverse=True)
    return result


def get_permissions_overview() -> Dict[str, List[Dict[str, Any]]]:
    """Appartenances aux rôles serveur + permissions explicites accordées/refusées au niveau serveur."""
    role_query = """
        SELECT
            sp.name AS login_name,
            sp.type_desc AS login_type,
            sp.is_disabled,
            sp.create_date,
            sp.modify_date,
            r.name AS server_role
        FROM sys.server_principals sp
        LEFT JOIN sys.server_role_members srm ON sp.principal_id = srm.member_principal_id
        LEFT JOIN sys.server_principals r ON srm.role_principal_id = r.principal_id
        WHERE sp.type IN ('S', 'U', 'G')
          AND sp.name NOT LIKE '##%'
        ORDER BY sp.name
    """
    perms_query = """
        SELECT
            pr.name AS grantee,
            pr.type_desc AS grantee_type,
            perm.permission_name,
            perm.state_desc
        FROM sys.server_permissions perm
        JOIN sys.server_principals pr ON perm.grantee_principal_id = pr.principal_id
        WHERE pr.name NOT LIKE '##%'
        ORDER BY pr.name, perm.permission_name
    """
    conn = _get_connection()
    try:
        roles = _execute_query(conn, role_query)
        perms = _execute_query(conn, perms_query)
        return {"role_memberships": roles, "explicit_permissions": perms}
    finally:
        conn.close()