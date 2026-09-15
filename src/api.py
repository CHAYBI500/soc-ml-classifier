"""
api.py
======
API FastAPI de triage ML L1 pour les alertes Wazuh.

Endpoints :
    GET  /health              -> {"status": "ok", "model_loaded": bool}
    POST /predict              -> classifie une alerte Wazuh brute (TP/FP + confiance)
    POST /simulate              -> injecte une alerte d'exemple aléatoire (démo dashboard)
    GET  /alerts/recent?limit=N -> historique en mémoire des dernières alertes traitées
    POST /alerts/{id}/status     -> transition new/acknowledged/resolved (triage manuel)
    POST /alerts/{id}/suppress   -> marque (rule_id, agent_name) "connu, ignorer désormais"
    DELETE /alerts/suppress/{rule_id}/{agent_name} -> réactive une règle précédemment ignorée
    GET  /alerts/critical         -> historique DURABLE (data/alerts.db) des alertes True
                                      Positive Critique/Élevée, survit aux redémarrages
    GET  /events/stream          -> flux Server-Sent Events (push temps réel alertes + stats)
    GET  /stats                  -> statistiques agrégées (taux TP, débit, confiance moyenne)
    GET  /model/importance       -> feature importances triées (top 12)
    GET  /model/categories       -> taxonomie des catégories de menace (slug/libellé/couleur)
    POST /ai/ask                 -> assistant IA (Gemini 3.1 Flash Lite) sur l'état du SOC
    GET  /sql/health              -> connectivité vers le SQL Server surveillé
    GET  /sql/sessions            -> connexions/sessions actives en direct (DMV)
    GET  /sql/users               -> utilisateurs actuellement connectés (agrégé)
    GET  /sql/permissions         -> rôles serveur + permissions explicites
    GET  /sql/security-events     -> alertes Wazuh de l'agent SQL Server, déjà classifiées ML
    GET  /hygiene/health           -> connectivité vers l'API REST du manager Wazuh
    GET  /hygiene/agents           -> liste des agents Wazuh
    GET  /hygiene/overview         -> score d'hygiène par agent (ports sensibles, correctifs)
    GET  /hygiene/agent/{id}/packages|ports|processes|hotfixes -> inventaire syscollector détaillé

Authentification admin (voir src/auth.py) :
    POST /auth/register       -> crée un compte admin (nécessite ADMIN_SETUP_KEY), envoie un code email
    POST /auth/verify-email   -> active le compte avec le code reçu par email
    POST /auth/resend-code    -> renvoie un code (register/login)
    POST /auth/login          -> étape 1 : email + mot de passe -> envoie un code OTP par email
    POST /auth/login/verify   -> étape 2 : email + code OTP -> ouvre la session (cookie httpOnly)
    POST /auth/logout         -> révoque la session courante
    GET  /auth/me             -> identité de l'admin authentifié
    GET  /auth/history        -> historique des connexions (email, nom, IP, machine)

Toutes les pages du dashboard et tous les endpoints ci-dessus (sauf /health, /predict,
/simulate et /auth/*) exigent une session admin valide (cookie), imposée par un
middleware global (voir require_admin_session ci-dessous) : impossible d'accéder au
dashboard ou aux données sans s'être authentifié au préalable.

Le dashboard statique (dashboard/index.html) est servi en dernier sur "/" via StaticFiles,
pour éviter tout problème CORS/file:// : le JS du dashboard appelle l'API en chemin relatif
(const API = ""), donc même origine, pas de souci CORS.

Lancement (dev, Windows, venv actif) :
    uvicorn src.api:app --host 0.0.0.0 --port 8000 --reload

Variable d'environnement nécessaire pour /ai/ask :
    setx GEMINI_API_KEY "ta_cle_api"      (Windows, nouveau terminal après)
    export GEMINI_API_KEY="ta_cle_api"    (Linux/WSL)

Dépendance supplémentaire pour /ai/ask :
    pip install google-genai

Variables d'environnement nécessaires pour /sql/* (voir src/sql_monitor.py pour le détail
et pour la création d'un login SQL dédié en lecture seule) :
    SQLSRV_HOST, SQLSRV_PORT, SQLSRV_DATABASE, SQLSRV_USER, SQLSRV_PASSWORD
    SQLSRV_TRUSTED_CONNECTION, SQLSRV_DRIVER, SQLSRV_WAZUH_AGENT_NAME

Dépendance supplémentaire pour /sql/* :
    pip install pyodbc   (+ driver ODBC 17 pour SQL Server installé sur la machine hôte de l'API)

NOTE IMPORTANTE (voir README section 11) : ce poste de dev tourne sous Windows.
La VM Wazuh (Linux, 10.212.2.170) doit pouvoir atteindre cette machine, port
8000 ouvert côté pare-feu Windows. À terme, héberger
cette API sur une VM Linux dédiée (ou la VM Wazuh elle-même) est recommandé
pour la stabilité et la disponibilité réseau, un poste de dev n'étant pas fiable
pour un service de production 24/7.
"""

from __future__ import annotations

import asyncio
import json
import os
import queue
import random
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

import joblib
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src import alerts_db
from src import auth as auth_module
from src.attack_category import CATEGORIES, derive_category
from src.feature_engineering import features_for_single_alert
from src.parse_wazuh import parse_alert
from src.sql_monitor import SqlMonitorError, get_active_sessions, get_active_users_summary, get_permissions_overview, test_connection
from src.wazuh_inventory import (
    WazuhApiError,
    compute_hygiene_score,
    get_hotfixes,
    get_packages,
    get_ports,
    get_processes,
    get_vulnerabilities,
    list_agents,
)
from src.wazuh_inventory import test_connection as wazuh_test_connection

# Charge les variables d'environnement depuis un fichier .env à la racine du projet (s'il existe),
# sans jamais écraser une variable déjà définie dans l'environnement (utile en prod / service).
# Voir .env.example pour le gabarit complet (SQLSRV_*, GEMINI_API_KEY).
load_dotenv()

# Journal durable des alertes critiques (voir src/alerts_db.py) — créé/migré au démarrage,
# même pattern que auth_db.init_db() dans src/auth.py.
alerts_db.init_db()

MODEL_PATH = Path("models/rf_classifier.joblib")
CATEGORY_MODEL_PATH = Path("models/rf_category_classifier.joblib")
DASHBOARD_DIR = Path("dashboard")
HISTORY_MAXLEN = 500
DEFAULT_CONFIDENCE_THRESHOLD = 0.6
# En dessous de ce seuil, _classify_category retombe sur "other" plutôt que d'afficher un
# label de catégorie peu fiable comme s'il était sûr (10 classes -> ~0.10 de base aléatoire,
# 0.4 laisse une marge raisonnable sans être trop strict).
MIN_CATEGORY_CONFIDENCE = 0.4
# Fenêtre de regroupement des alertes répétées dans le flux (même rule_id + agent_name) :
# évite qu'une règle qui se déclenche en rafale (toutes les quelques secondes) inonde le
# flux d'une ligne par occurrence. Voir _classify / _active_alert_groups ci-dessous.
ALERT_GROUP_WINDOW_SECONDS = 120
# Fenêtre de corrélation multi-signaux : si un même agent accumule plusieurs catégories de
# menace DISTINCTES dans cette fenêtre, l'alerte courante est marquée comme signal de chaîne
# d'attaque potentielle (voir _classify / _agent_category_window).
CHAIN_WINDOW_MINUTES = 20
CHAIN_MIN_DISTINCT_CATEGORIES = 2
# Paliers de priority_label (voir _compute_priority) jugés assez importants pour déclencher une
# notification côté client (dashboard/index.html) — décision de triage prise ICI, pas dans le
# frontend, qui se contente de refléter le champ "should_notify" ci-dessous sans logique propre.
NOTIFY_PRIORITY_LABELS = {"Critique", "Élevée"}
# rule_id connus comme bruit opérationnel/housekeeping (mêmes règles que les templates de
# bruit de src/seed_alerts.py) : court-circuités directement en catégorie "operational" avant
# même d'appeler le modèle de catégorie — garde-fou indépendant du ML, extensible sans toucher
# au code via la variable d'environnement NON_ACTIONABLE_RULE_IDS (CSV de rule_id).
_NON_ACTIONABLE_RULE_IDS = {"651", "591", "502", "503", "1002", "5501"} | {
    rid.strip() for rid in os.environ.get("NON_ACTIONABLE_RULE_IDS", "").split(",") if rid.strip()
}
_VALID_ALERT_STATUSES = {"new", "acknowledged", "resolved"}
# "gemini-2.5-flash-lite" est toujours listé par l'API mais renvoie 404 NOT_FOUND à la génération
# ("no longer available to new users") pour les clés API créées après la sortie de Gemini 3.
# "gemini-flash-lite-latest" (alias mobile de Google) fonctionnait mais s'est mesuré à 6-19s de
# latence par réponse sur cette clé — beaucoup trop lent pour un assistant temps réel. Benchmarké
# contre "gemini-3.1-flash-lite" (nommé explicitement, pas un alias) : 0.5-0.9s constant sur des
# prompts réalistes, qualité de réponse équivalente. D'où le choix ci-dessous.
GEMINI_MODEL = "gemini-3.1-flash-lite"
# Nom exact de l'agent Wazuh installé sur la VM Windows Server 2019 / SQL Server 2016.
# Si non défini, /sql/security-events retombe sur un filtrage par sous-chaîne "sql"
# (insensible à la casse) dans agent_name.
SQLSRV_WAZUH_AGENT_NAME = os.environ.get("SQLSRV_WAZUH_AGENT_NAME")

app = FastAPI(
    title="SOC ML Classifier API",
    description="API de triage ML L1 des alertes Wazuh (True Positive / False Positive).",
    version="1.0.0",
)

# CORS : le dashboard est servi en même origine que l'API (voir montage StaticFiles
# en bas de fichier), donc aucun cross-origin n'est nécessaire pour lui. n8n et
# l'intégration Wazuh (custom-ml-triage.py) appellent l'API en HTTP serveur-à-serveur,
# ce que CORS ne concerne pas (CORS est une restriction appliquée par les navigateurs).
# Un wildcard "*" combiné à allow_credentials=True est de toute façon dangereux
# maintenant que l'admin s'authentifie par cookie de session : on restreint donc aux
# origines explicitement autorisées via CORS_ALLOWED_ORIGINS (liste séparée par des
# virgules), vide par défaut.
_cors_origins = [o.strip() for o in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Authentification admin (voir src/auth.py) --------------------------------
app.include_router(auth_module.router)

# Chemins accessibles sans session admin : la page de login elle-même, les endpoints
# /auth/* (login/register/etc, forcément publics), /health (supervision), et /predict
# + /simulate qui sont des webhooks machine-à-machine appelés directement par le
# manager Wazuh et par n8n (pas de navigateur, donc pas de session possible).
_PUBLIC_PATHS = {"/login.html", "/favicon.ico", "/health", "/predict", "/simulate"}


@app.middleware("http")
async def require_admin_session(request: Request, call_next):
    path = request.url.path
    if path in _PUBLIC_PATHS or path.startswith("/auth/"):
        return await call_next(request)

    if auth_module.get_admin_from_request(request) is None:
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            return RedirectResponse(url="/login.html", status_code=302)
        return JSONResponse(status_code=401, content={"detail": "Authentification requise."})

    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response

# --- État en mémoire (process unique, cohérent avec un déploiement mono-instance de dev/petit SOC) ---
_model_bundle: Optional[Dict[str, Any]] = None
_category_model_bundle: Optional[Dict[str, Any]] = None
_alert_history: Deque[Dict[str, Any]] = deque(maxlen=HISTORY_MAXLEN)
# Regroupe les occurrences répétées d'une même règle sur le même agent (rafale toutes les
# quelques secondes) en une seule entrée de _alert_history au lieu d'une par occurrence —
# voir _classify. Clé = (rule_id, agent_name) -> entrée (dict) actuellement affichée dans
# le flux pour ce couple, tant qu'elle reste dans la fenêtre ALERT_GROUP_WINDOW_SECONDS.
_active_alert_groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
# Historique glissant des catégories récentes par agent (hors "other"/"operational"), utilisé
# pour détecter des signaux corrélés (plusieurs catégories distinctes sur le même agent en peu
# de temps = potentielle chaîne d'attaque) — voir _classify, CHAIN_WINDOW_MINUTES.
_agent_category_window: Dict[str, Deque[Tuple[datetime, str]]] = {}
# (rule_id, agent_name) qu'un admin a explicitement marqués "connu, ignorer désormais" via
# POST /alerts/{id}/suppress — toute nouvelle alerte correspondante arrive directement en
# status="suppressed" (voir _classify), jusqu'à un DELETE /alerts/suppress/{rule_id}/{agent}.
_suppressed_keys: set[Tuple[str, str]] = set()
_stats = {
    "total": 0,
    "true_positive": 0,
    "false_positive": 0,
    "start_time": time.time(),
    "category_counts": {slug: 0 for slug in CATEGORIES},
}
_gemini_client: Optional[Any] = None  # instancié paresseusement, voir _get_gemini_client()

# --- Diffusion temps réel (SSE, voir /events/stream) ---------------------------------------
# Remplace le polling à 5s du dashboard pour le flux d'alertes : chaque nouvelle prédiction
# (_classify, appelée par /predict et /simulate) est immédiatement poussée aux clients
# connectés au lieu que ceux-ci doivent réinterroger /alerts/recent en boucle. Implémenté avec
# queue.Queue (thread-safe stdlib) plutôt qu'asyncio.Queue car /predict est une route FastAPI
# synchrone exécutée dans le threadpool de Starlette (pas la boucle asyncio) — utiliser
# asyncio.Queue depuis ce thread nécessiterait un aller-retour explicite vers la boucle
# événementielle (call_soon_threadsafe) ; queue.Queue évite ce piège au prix d'un polling
# interne à intervalle court (voir events_stream) côté générateur SSE, largement suffisant
# ici (latence perçue de l'ordre de la centaine de ms, contre 5000ms en polling HTTP classique).
_sse_subscribers: List["queue.Queue[str]"] = []
_sse_lock = threading.Lock()
_SSE_QUEUE_MAXSIZE = 200


def _publish_event(event_type: str, payload: Dict[str, Any]) -> None:
    """Pousse un événement à tous les clients SSE connectés (no-op si aucun)."""
    if not _sse_subscribers:
        return
    message = f"event: {event_type}\ndata: {json.dumps(payload, ensure_ascii=False, default=str)}\n\n"
    with _sse_lock:
        subscribers = list(_sse_subscribers)
    for q in subscribers:
        try:
            q.put_nowait(message)
        except queue.Full:
            # Client lent/déconnecté qui n'a pas vidé sa file : on laisse tomber ses events
            # plutôt que de bloquer la diffusion pour tous les autres clients connectés.
            pass

# Jeu d'alertes de démo embarqué pour /simulate, représentatif des groupes surveillés
# (attack, sshd, web, firewall, authentication_failed) sans dépendre de vraies alertes Wazuh.
_SAMPLE_ALERTS: List[Dict[str, Any]] = [
    {
        "rule": {
            "id": 5710,
            "level": 10,
            "description": "sshd: Multiple authentication failures.",
            "groups": ["authentication_failed", "sshd"],
            "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]},
            "firedtimes": 8,
        },
        "agent": {"id": "003", "name": "web-srv-01"},
        "data": {"srcip": "185.220.101.45", "dstip": "172.17.1.115"},
        "timestamp": None,
    },
    {
        "rule": {
            "id": 100200,
            "level": 12,
            "description": "AbuseIPDB: malicious IP detected in inbound traffic.",
            "groups": ["attack", "firewall"],
            "mitre": {"id": ["T1071"], "tactic": ["Command and Control"]},
            "firedtimes": 3,
        },
        "agent": {"id": "001", "name": "pfsense-fw"},
        "data": {"srcip": "45.155.205.20", "dstip": "10.212.2.170"},
        "timestamp": None,
    },
    {
        "rule": {
            "id": 87105,
            "level": 12,
            "description": "VirusTotal: Malware detected in file (EICAR test signature).",
            "groups": ["virustotal", "syscheck", "malware"],
            "mitre": {"id": ["T1204"], "tactic": ["Execution"]},
            "firedtimes": 1,
        },
        "agent": {"id": "003", "name": "web-srv-01"},
        "data": {"srcip": None, "dstip": None},
        "timestamp": None,
    },
    {
        "rule": {
            "id": 651,
            "level": 3,
            "description": "pfSense: Firewall rule match, connection blocked (routine noise).",
            "groups": ["firewall"],
            "mitre": {"id": [], "tactic": []},
            "firedtimes": 42,
        },
        "agent": {"id": "001", "name": "pfsense-fw"},
        "data": {"srcip": "192.168.1.50", "dstip": "8.8.8.8"},
        "timestamp": None,
    },
    {
        "rule": {
            "id": 591,
            "level": 0,
            "description": "Log file rotated.",
            "groups": ["ossec"],
            "mitre": {"id": [], "tactic": []},
            "firedtimes": 1,
        },
        "agent": {"id": "002", "name": "ubuntu-agent-115"},
        "data": {"srcip": None, "dstip": None},
        "timestamp": None,
    },
    {
        "rule": {
            "id": 31151,
            "level": 8,
            "description": "Web attack detected: SQL injection attempt.",
            "groups": ["attack", "web"],
            "mitre": {"id": ["T1190"], "tactic": ["Initial Access"]},
            "firedtimes": 5,
        },
        "agent": {"id": "003", "name": "web-srv-01"},
        "data": {"srcip": "91.240.118.222", "dstip": "172.17.1.115"},
        "timestamp": None,
    },
    {
        "rule": {
            "id": 60122,
            "level": 5,
            "description": "PowerShell script block logged (obfuscated content detected).",
            "groups": ["windows", "powershell"],
            "mitre": {"id": ["T1059.001"], "tactic": ["Execution"]},
            "firedtimes": 2,
        },
        "agent": {"id": "004", "name": "win-workstation-07"},
        "data": {"srcip": None, "dstip": None},
        "timestamp": None,
    },
]


class PredictResponse(BaseModel):
    prediction: str
    confidence: float
    rule_id: str
    rule_description: str
    category: str
    category_label: str
    category_confidence: float
    category_source: str  # "model" (rf_category_classifier chargé) ou "heuristic" (fallback)


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool


class AlertStatusRequest(BaseModel):
    status: str  # "new" | "acknowledged" | "resolved"


class StatsResponse(BaseModel):
    total: int
    true_positive: int
    false_positive: int
    tp_rate: float
    alerts_per_min: float
    avg_confidence: float
    category_counts: Dict[str, int] = Field(default_factory=dict)


class AiAskRequest(BaseModel):
    question: str
    context: Optional[Dict[str, Any]] = None
    history: Optional[List[Dict[str, str]]] = None


class AiAskResponse(BaseModel):
    answer: str


def _load_model() -> Optional[Dict[str, Any]]:
    global _model_bundle
    if _model_bundle is not None:
        return _model_bundle
    if not MODEL_PATH.exists():
        return None
    _model_bundle = joblib.load(MODEL_PATH)
    return _model_bundle


def _load_category_model() -> Optional[Dict[str, Any]]:
    global _category_model_bundle
    if _category_model_bundle is not None:
        return _category_model_bundle
    if not CATEGORY_MODEL_PATH.exists():
        return None
    _category_model_bundle = joblib.load(CATEGORY_MODEL_PATH)
    return _category_model_bundle


def _classify_category(raw_alert: Dict[str, Any], features_df) -> Dict[str, Any]:
    """
    Détermine la catégorie de menace (sql, malware, bruteforce, recon, web, endpoint,
    network, other). Utilise le modèle RandomForest multi-classe s'il est chargé, sinon
    retombe sur la dérivation heuristique directe (src/attack_category.derive_category) —
    permet à cette fonctionnalité de marcher même avant le premier entraînement du modèle
    de catégorie (`python -m src.train_category_model`).
    """
    bundle = _load_category_model()
    if bundle is not None:
        clf = bundle["model"]
        feature_columns = bundle["feature_columns"]
        X = features_df[feature_columns].fillna(0)
        proba = clf.predict_proba(X)[0]
        classes = clf.classes_
        best_idx = int(proba.argmax())
        slug = str(classes[best_idx])
        confidence = float(proba[best_idx])
        source = "model"
        if confidence < MIN_CATEGORY_CONFIDENCE:
            slug = "other"
    else:
        record = parse_alert(raw_alert) or {}
        slug = derive_category(record)
        confidence = 1.0
        source = "heuristic"

    meta = CATEGORIES.get(slug, CATEGORIES["other"])
    return {"category": slug, "category_label": meta["label"], "category_confidence": round(confidence, 4), "category_source": source}


def _compute_priority(
    rule_level: Optional[int], confidence: float, category_weight: float, has_mitre: bool, is_chain_signal: bool
) -> Tuple[int, str]:
    """Score de priorité composite (0-100) pour aider un analyste à voir ce qui est critique
    MAINTENANT, indépendamment de l'ordre chronologique du flux. Combine la sévérité Wazuh
    (rule_level), la confiance du modèle TP/FP, la criticité éditoriale de la catégorie
    (CATEGORIES[...]["weight"]), la présence d'une technique MITRE identifiée, et un bonus si
    l'alerte fait partie d'un signal de chaîne multi-catégories (voir _agent_category_window).
    Seuils de label alignés sur severityOf() côté dashboard (index.html) pour rester cohérent
    visuellement entre le score serveur et le bucketing déjà affiché côté client.
    """
    level_component = min((rule_level or 0) / 15, 1.0) * 40
    confidence_component = max(0.0, min(confidence, 1.0)) * 25
    category_component = max(0.0, min(category_weight, 1.0)) * 15
    mitre_component = 10 if has_mitre else 0
    chain_component = 10 if is_chain_signal else 0
    score = round(level_component + confidence_component + category_component + mitre_component + chain_component)
    score = max(0, min(score, 100))

    if score >= 75:
        label = "Critique"
    elif score >= 50:
        label = "Élevée"
    elif score >= 25:
        label = "Moyenne"
    else:
        label = "Faible"
    return score, label


GEMINI_TIMEOUT_MS = int(os.environ.get("GEMINI_TIMEOUT_MS", "12000"))


def _get_gemini_client():
    """Instancie le client Gemini une seule fois (paresseux, pour ne pas planter au démarrage
    si google-genai n'est pas installé ou si la clé n'est pas encore définie).

    http_options.timeout est explicite (12s par défaut) : sans lui, un appel Gemini qui reste
    bloqué (même flakiness réseau/DNS intermittente que celle déjà observée sur ce LAN pour
    SMTP/SQL Server, voir src/mailer.py) n'a AUCUNE limite de temps côté client et /ai/ask
    reste pendu indéfiniment ("endpoint injoignable" côté dashboard) au lieu d'échouer
    proprement et vite pour laisser le retry de ai_ask() prendre le relais. Le SDK google-genai
    impose un délai minimum de 10s (en dessous : 400 INVALID_ARGUMENT "Manually set deadline
    is too short" — c'est ce qui rendait /ai/ask systématiquement injoignable avec l'ancien
    défaut de 8s) ; 12s laisse une marge de sécurité au-dessus de ce plancher."""
    global _gemini_client
    if _gemini_client is not None:
        return _gemini_client

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="GEMINI_API_KEY non définie côté serveur. Définis-la puis redémarre l'API.",
        )

    try:
        from google import genai
        from google.genai import types
    except ImportError as exc:
        raise HTTPException(
            status_code=500,
            detail="Package google-genai manquant. Installe-le avec `pip install google-genai`.",
        ) from exc

    _gemini_client = genai.Client(
        api_key=api_key,
        http_options=types.HttpOptions(timeout=GEMINI_TIMEOUT_MS),
    )
    return _gemini_client


AI_SYSTEM_PROMPT = (
    "Tu es l'assistant IA intégré à la console SOC de cette organisation : Wazuh (collecte "
    "d'alertes) + un classifieur ML L1 (Random Forest) qui trie True Positive/False Positive, "
    "catégorise la menace (bruteforce, malware, sql, web, recon, endpoint, network, ddos, "
    "vulnerability, other) et calcule un score de priorité composite (niveau Wazuh + confiance "
    "+ poids de catégorie + technique MITRE + signal de chaîne multi-catégories). Le dashboard "
    "couvre aussi le monitoring SQL Server (sessions/rôles/permissions live) et l'hygiène IT "
    "(vulnérabilités, ports, correctifs des agents Wazuh).\n"
    "Ton rôle : te comporter comme un analyste SOC senior qui répond à ses collègues — pertinent, "
    "factuel, jamais évasif sur ce qui concerne CETTE plateforme (alertes, priorisation, "
    "catégories, fonctionnement du classifieur, SQL Server surveillé, hygiène des postes). Tu "
    "peux expliquer comment un score/une catégorie/une priorité a été calculé(e) à partir des "
    "règles ci-dessus, pas seulement réciter les chiffres bruts.\n"
    "Registre : professionnel, direct, sans familiarité ni emoji — comme à l'écrit entre "
    "analystes, pas comme un chatbot grand public.\n"
    "Format, à respecter TOUJOURS :\n"
    "- Réponds UNIQUEMENT à la question posée. Pas d'introduction, pas de reformulation de la "
    "question, pas de conclusion générique, pas de formule de politesse.\n"
    "- 1 à 3 phrases courtes par défaut, ou une liste à puces courte si plusieurs éléments. "
    "Ne développe en détail que si l'utilisateur le demande explicitement.\n"
    "- Va droit au chiffre/fait demandé en premier, sans préambule.\n"
    "Sur le fond : tu t'appuies strictement sur le contexte JSON fourni (statistiques serveur, "
    "échantillon d'alertes récentes avec leur priorité). Si une donnée n'est pas présente dans "
    "le contexte, dis-le en une phrase au lieu de l'inventer — ne devine jamais un chiffre. "
    "Priorise la sécurité : signale en premier les alertes de priorité Critique/Élevée. Si la "
    "question sort clairement du périmètre de cette plateforme SOC, dis-le en une phrase plutôt "
    "que d'inventer une réponse hors sujet."
)


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    bundle = _load_model()
    return HealthResponse(status="ok", model_loaded=bundle is not None)


def _classify(raw_alert: Dict[str, Any]) -> PredictResponse:
    bundle = _load_model()
    if bundle is None:
        raise HTTPException(
            status_code=503,
            detail="Modèle non chargé. Entraînez le modèle via `python -m src.train_model` puis redémarrez l'API.",
        )

    clf = bundle["model"]
    feature_columns = bundle["feature_columns"]

    try:
        features_df = features_for_single_alert(raw_alert)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    X = features_df[feature_columns].fillna(0)
    proba = float(clf.predict_proba(X)[0, 1])
    label = "True Positive" if proba >= DEFAULT_CONFIDENCE_THRESHOLD else "False Positive"

    rule_id = str(features_df.get("_meta_rule_id", [""]).iloc[0]) if "_meta_rule_id" in features_df else ""
    rule_description = (
        str(features_df.get("_meta_rule_description", [""]).iloc[0])
        if "_meta_rule_description" in features_df
        else ""
    )

    if rule_id in _NON_ACTIONABLE_RULE_IDS:
        # Bruit opérationnel/housekeeping connu (voir _NON_ACTIONABLE_RULE_IDS) : court-circuit
        # avant le modèle ML, jamais prédit par le classifieur de catégorie lui-même.
        meta = CATEGORIES["operational"]
        category_info = {
            "category": "operational",
            "category_label": meta["label"],
            "category_confidence": 1.0,
            "category_source": "rule_id_override",
        }
    else:
        category_info = _classify_category(raw_alert, features_df)

    response = PredictResponse(
        prediction=label,
        confidence=round(proba, 4),
        rule_id=rule_id,
        rule_description=rule_description,
        **category_info,
    )

    # Mise à jour de l'historique + stats en mémoire (utilisé par le dashboard)
    _stats["total"] += 1
    if label == "True Positive":
        _stats["true_positive"] += 1
    else:
        _stats["false_positive"] += 1
    _stats["category_counts"][category_info["category"]] = (
        _stats["category_counts"].get(category_info["category"], 0) + 1
    )

    now_iso = datetime.now(timezone.utc).isoformat()
    agent_name = raw_alert.get("agent", {}).get("name", "unknown")
    group_key = (rule_id, agent_name)
    now_dt = datetime.now(timezone.utc)

    # Corrélation multi-signaux : une catégorie "actionnable" (ni other ni operational) vient
    # allonger la fenêtre glissante de cet agent ; si plusieurs catégories DISTINCTES s'y
    # trouvent, cette alerte est marquée comme signal de chaîne d'attaque potentielle.
    category_slug = category_info["category"]
    window = _agent_category_window.setdefault(agent_name, deque())
    if category_slug not in ("other", "operational"):
        window.append((now_dt, category_slug))
    chain_cutoff = now_dt - timedelta(minutes=CHAIN_WINDOW_MINUTES)
    while window and window[0][0] < chain_cutoff:
        window.popleft()
    distinct_categories = sorted({c for _, c in window})
    is_chain_signal = len(distinct_categories) >= CHAIN_MIN_DISTINCT_CATEGORIES

    has_mitre = bool(raw_alert.get("rule", {}).get("mitre", {}).get("id"))
    category_weight = float(CATEGORIES.get(category_slug, CATEGORIES["other"]).get("weight", 0.1))
    priority_score, priority_label = _compute_priority(
        rule_level=raw_alert.get("rule", {}).get("level"),
        confidence=proba,
        category_weight=category_weight,
        has_mitre=has_mitre,
        is_chain_signal=is_chain_signal,
    )

    initial_status = "suppressed" if group_key in _suppressed_keys else "new"

    # Regroupe les occurrences répétées d'une même règle sur le même agent (rafale toutes
    # les quelques secondes) en une seule entrée du flux au lieu d'une par occurrence — voir
    # _active_alert_groups. _stats/category_counts ci-dessus comptent quand même CHAQUE
    # alerte brute reçue : seule la vue "flux" est agrégée, pas le volume réel.
    active_entry = _active_alert_groups.get(group_key)
    if active_entry is not None:
        last_seen_dt = datetime.fromisoformat(active_entry["last_seen"])
        if (datetime.now(timezone.utc) - last_seen_dt).total_seconds() > ALERT_GROUP_WINDOW_SECONDS:
            active_entry = None

    # Triage automatique façon SOC L1 : décide ICI (côté modèle/serveur), pas dans le dashboard,
    # si CETTE occurrence mérite de notifier un analyste. Un incident non notifiable au premier
    # coup (ex: "Windows application error", priorité Moyenne) peut le devenir plus tard si sa
    # situation s'aggrave réellement (ex: passage en signal de chaîne multi-catégories qui fait
    # franchir le seuil "Élevée") — au même titre qu'un analyste qui ignore un bruit répétitif
    # mais réagit si celui-ci dégénère. À l'inverse, un incident déjà notifié ne renotifie pas à
    # chaque répétition tant qu'il reste dans la même fenêtre de regroupement : le compteur "×N"
    # du flux suffit à en suivre la fréquence sans re-solliciter l'analyste pour rien.
    previous_priority_label = active_entry["priority_label"] if active_entry is not None else None
    is_notify_worthy = label == "True Positive" and priority_label in NOTIFY_PRIORITY_LABELS
    if group_key in _suppressed_keys:
        should_notify = False
    elif active_entry is not None:
        should_notify = is_notify_worthy and previous_priority_label not in NOTIFY_PRIORITY_LABELS
    else:
        should_notify = is_notify_worthy

    if active_entry is not None:
        active_entry["timestamp"] = now_iso
        active_entry["last_seen"] = now_iso
        active_entry["repeat_count"] += 1
        active_entry["prediction"] = label
        active_entry["confidence"] = round(proba, 4)
        active_entry["category"] = category_info["category"]
        active_entry["category_label"] = category_info["category_label"]
        active_entry["category_confidence"] = category_info["category_confidence"]
        active_entry["priority_score"] = priority_score
        active_entry["priority_label"] = priority_label
        active_entry["is_chain_signal"] = is_chain_signal
        active_entry["chain_categories"] = distinct_categories
        active_entry["should_notify"] = should_notify
        if group_key in _suppressed_keys:
            active_entry["status"] = "suppressed"
        history_entry = active_entry
        try:
            _alert_history.remove(history_entry)
        except ValueError:
            pass
        _alert_history.appendleft(history_entry)
    else:
        history_entry = {
            "id": uuid.uuid4().hex[:12],
            "timestamp": now_iso,
            "first_seen": now_iso,
            "last_seen": now_iso,
            "repeat_count": 1,
            "rule_id": rule_id,
            "rule_description": rule_description,
            "prediction": label,
            "confidence": round(proba, 4),
            "agent_name": agent_name,
            "rule_level": raw_alert.get("rule", {}).get("level"),
            "rule_groups": ",".join(raw_alert.get("rule", {}).get("groups", []) or []) or None,
            "srcip": raw_alert.get("data", {}).get("srcip"),
            "dstip": raw_alert.get("data", {}).get("dstip"),
            "rule_mitre_id": ",".join(raw_alert.get("rule", {}).get("mitre", {}).get("id", []) or []) or None,
            "rule_mitre_tactic": ",".join(raw_alert.get("rule", {}).get("mitre", {}).get("tactic", []) or []) or None,
            "category": category_info["category"],
            "category_label": category_info["category_label"],
            "category_confidence": category_info["category_confidence"],
            "priority_score": priority_score,
            "priority_label": priority_label,
            "is_chain_signal": is_chain_signal,
            "chain_categories": distinct_categories,
            "status": initial_status,
            "should_notify": should_notify,
        }
        _alert_history.appendleft(history_entry)
        _active_alert_groups[group_key] = history_entry

    # Journal durable (data/alerts.db). Deux écritures distinctes :
    # - critical_alerts : uniquement les True Positive de priorité "Critique"/"Élevée",
    #   journal d'audit dédié (voir src/alerts_db.py).
    # - alert_log + stats_totals : TOUTE alerte traitée, pour que l'API puisse reconstruire
    #   _alert_history / _stats au prochain démarrage (voir on_startup ci-dessous) au lieu de
    #   repartir de zéro à chaque redémarrage — c'est cette seconde écriture qui rend le flux
    #   "logs bruts" et "classification" persistant côté dashboard.
    if label == "True Positive" and priority_label in ("Critique", "Élevée"):
        alerts_db.upsert_critical_alert(history_entry)
    alerts_db.upsert_alert_log(history_entry)
    alerts_db.save_stats(
        _stats["total"], _stats["true_positive"], _stats["false_positive"], dict(_stats["category_counts"])
    )

    # Diffusion temps réel : le dashboard reçoit cette alerte immédiatement via /events/stream
    # au lieu d'attendre le prochain cycle de polling (voir _publish_event ci-dessus). Le champ
    # "id" stable permet au dashboard de distinguer une mise à jour (répétition agrégée) d'une
    # nouvelle alerte — voir dashboard/index.html::connectEventStream.
    _publish_event("alert", history_entry)
    _publish_event(
        "stats",
        {
            "total": _stats["total"],
            "true_positive": _stats["true_positive"],
            "false_positive": _stats["false_positive"],
            "category_counts": dict(_stats["category_counts"]),
        },
    )

    return response


@app.post("/predict", response_model=PredictResponse)
def predict(raw_alert: Dict[str, Any]) -> PredictResponse:
    """Reçoit une alerte Wazuh brute (JSON tel qu'émis par le manager) et retourne la classification."""
    return _classify(raw_alert)


@app.post("/simulate", response_model=PredictResponse)
def simulate() -> PredictResponse:
    """
    Injecte une alerte d'exemple aléatoire parmi le jeu de test embarqué.
    ATTENTION : ce mode est purement démonstratif, il NE reflète PAS les vraies
    alertes Wazuh du réseau surveillé. Le dashboard officiel n'appelle plus cet
    endpoint (bouton simulation retiré) ; il reste disponible ici pour des tests
    manuels via curl/Postman/Swagger si besoin.
    """
    sample = random.choice(_SAMPLE_ALERTS)
    return _classify(sample)


@app.get("/alerts/recent")
def alerts_recent(limit: int = 20) -> List[Dict[str, Any]]:
    limit = max(1, min(limit, HISTORY_MAXLEN))
    return list(_alert_history)[:limit]


def _find_alert_by_id(alert_id: str) -> Optional[Dict[str, Any]]:
    for entry in _alert_history:
        if entry.get("id") == alert_id:
            return entry
    return None


@app.post("/alerts/{alert_id}/status")
def set_alert_status(alert_id: str, payload: AlertStatusRequest) -> Dict[str, Any]:
    """Fait transitionner une alerte entre new/acknowledged/resolved — triage manuel par
    l'analyste, indépendant du modèle ML. "resolved" ferme aussi l'incident en cours
    (_active_alert_groups) : la prochaine occurrence de la même règle/agent redémarre une
    entrée "new" plutôt que de continuer à faire vivre celle-ci."""
    if payload.status not in _VALID_ALERT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"status invalide : {payload.status!r} (attendu : {sorted(_VALID_ALERT_STATUSES)}).",
        )
    entry = _find_alert_by_id(alert_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Alerte introuvable (hors historique en mémoire).")

    entry["status"] = payload.status
    if payload.status == "resolved":
        group_key = (entry.get("rule_id"), entry.get("agent_name"))
        if _active_alert_groups.get(group_key) is entry:
            del _active_alert_groups[group_key]
    alerts_db.update_status(alert_id, payload.status)
    return {"id": alert_id, "status": entry["status"]}


@app.post("/alerts/{alert_id}/suppress")
def suppress_alert(alert_id: str) -> Dict[str, Any]:
    """Marque le couple (rule_id, agent_name) de cette alerte comme "connu, ignorer désormais" :
    toute future occurrence arrivera directement en status="suppressed" (voir _classify),
    jusqu'à un DELETE /alerts/suppress/{rule_id}/{agent_name}."""
    entry = _find_alert_by_id(alert_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Alerte introuvable (hors historique en mémoire).")
    group_key = (entry.get("rule_id"), entry.get("agent_name"))
    _suppressed_keys.add(group_key)
    entry["status"] = "suppressed"
    alerts_db.update_status(alert_id, "suppressed")
    return {"rule_id": group_key[0], "agent_name": group_key[1], "suppressed": True}


@app.delete("/alerts/suppress/{rule_id}/{agent_name}")
def unsuppress_alert(rule_id: str, agent_name: str) -> Dict[str, Any]:
    _suppressed_keys.discard((rule_id, agent_name))
    return {"rule_id": rule_id, "agent_name": agent_name, "suppressed": False}


@app.get("/alerts/critical")
def critical_alerts(
    limit: int = 100,
    since: Optional[str] = None,
    until: Optional[str] = None,
    agent_name: Optional[str] = None,
    category: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Historique DURABLE (data/alerts.db, survit aux redémarrages) des alertes True Positive
    de priorité Critique/Élevée — voir alerts_db.upsert_critical_alert dans _classify.
    since/until : timestamps ISO8601, filtrés sur last_seen (date exacte de dernière occurrence).
    """
    limit = max(1, min(limit, 1000))
    return alerts_db.list_critical_alerts(
        limit=limit, since=since, until=until, agent_name=agent_name, category=category
    )


@app.get("/events/stream")
async def events_stream(request: Request):
    """
    Flux Server-Sent Events (text/event-stream) : pousse chaque nouvelle alerte classifiée
    (event "alert") et les compteurs mis à jour (event "stats") en temps réel, dès que
    /predict ou /simulate traite une alerte — voir _publish_event(). Remplace le polling
    à 5s pour le flux d'alertes de la Vue L1 (le dashboard garde un polling de secours pour
    les vues qui ne dépendent pas d'un événement, ex: SQL Server, Hygiène IT).

    Authentification : couverte par le middleware require_admin_session comme le reste du
    dashboard (ce chemin n'est pas dans _PUBLIC_PATHS). Le client (EventSource) doit être
    créé avec {withCredentials: true} pour que le cookie de session soit transmis, EventSource
    ne l'envoyant pas par défaut même en same-origin.
    """
    client_queue: "queue.Queue[str]" = queue.Queue(maxsize=_SSE_QUEUE_MAXSIZE)
    with _sse_lock:
        _sse_subscribers.append(client_queue)

    async def event_generator():
        try:
            yield "retry: 3000\n\n"
            yield ": connected\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    message = await asyncio.to_thread(client_queue.get, True, 15)
                    yield message
                except queue.Empty:
                    yield ": keepalive\n\n"  # évite qu'un proxy intermédiaire coupe la connexion idle
        finally:
            with _sse_lock:
                if client_queue in _sse_subscribers:
                    _sse_subscribers.remove(client_queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@app.get("/stats", response_model=StatsResponse)
def stats() -> StatsResponse:
    total = _stats["total"]
    tp = _stats["true_positive"]
    fp = _stats["false_positive"]
    elapsed_min = max((time.time() - _stats["start_time"]) / 60.0, 1e-6)

    avg_confidence = 0.0
    if _alert_history:
        avg_confidence = sum(a["confidence"] for a in _alert_history) / len(_alert_history)

    return StatsResponse(
        total=total,
        true_positive=tp,
        false_positive=fp,
        tp_rate=round(tp / total, 4) if total else 0.0,
        alerts_per_min=round(total / elapsed_min, 2),
        avg_confidence=round(avg_confidence, 4),
        category_counts=dict(_stats["category_counts"]),
    )


@app.get("/model/importance")
def model_importance() -> List[Dict[str, Any]]:
    bundle = _load_model()
    if bundle is None:
        raise HTTPException(status_code=503, detail="Modèle non chargé.")

    clf = bundle["model"]
    feature_columns = bundle["feature_columns"]
    importances = sorted(
        zip(feature_columns, clf.feature_importances_.tolist()), key=lambda x: x[1], reverse=True
    )
    top12 = [{"feature": name, "importance": round(imp, 4)} for name, imp in importances[:12]]
    return top12


@app.get("/model/categories")
def model_categories() -> Dict[str, Any]:
    """
    Taxonomie des catégories de menace (slug -> libellé FR + couleur dashboard) et indique
    si le modèle multi-classe est chargé (sinon /predict retombe sur la classification
    heuristique, voir _classify_category). Source unique de vérité consommée par le
    dashboard pour construire badges/légende sans dupliquer la taxonomie côté JS.
    """
    return {"categories": CATEGORIES, "model_loaded": _load_category_model() is not None}


@app.get("/sql/health")
def sql_health() -> Dict[str, Any]:
    """Vérifie la connectivité vers le SQL Server surveillé (VM Windows Server 2019 / SQL Server 2016)."""
    try:
        return test_connection()
    except SqlMonitorError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/sql/sessions")
def sql_sessions() -> List[Dict[str, Any]]:
    """Connexions/sessions actives en direct (sys.dm_exec_sessions / sys.dm_exec_connections)."""
    try:
        return get_active_sessions()
    except SqlMonitorError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/sql/users")
def sql_users() -> List[Dict[str, Any]]:
    """Résumé des utilisateurs actuellement connectés (agrégation des sessions actives par login)."""
    try:
        return get_active_users_summary()
    except SqlMonitorError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/sql/permissions")
def sql_permissions() -> Dict[str, List[Dict[str, Any]]]:
    """Appartenances aux rôles serveur + permissions explicites (niveau serveur SQL)."""
    try:
        return get_permissions_overview()
    except SqlMonitorError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/sql/security-events")
def sql_security_events(limit: int = 25) -> List[Dict[str, Any]]:
    """
    Alertes Wazuh déjà classifiées par le pipeline ML, filtrées sur l'agent de la VM
    SQL Server (échecs d'authentification, changements de permissions détectés, etc.).
    Ne fait AUCUNE requête SQL directe : relit simplement l'historique en mémoire déjà
    peuplé par /predict, pour corréler l'état "live" (DMV) avec l'historique de sécurité.
    """
    limit = max(1, min(limit, HISTORY_MAXLEN))

    def matches(alert: Dict[str, Any]) -> bool:
        name = (alert.get("agent_name") or "").lower()
        if SQLSRV_WAZUH_AGENT_NAME:
            return name == SQLSRV_WAZUH_AGENT_NAME.lower()
        return "sql" in name

    filtered = [a for a in _alert_history if matches(a)]
    return filtered[:limit]


# --- Hygiène IT (inventaire syscollector via l'API REST du manager Wazuh) ---
# Distinct des alertes de sécurité ci-dessus : ici on interroge l'état/la posture des agents
# (logiciels installés, ports ouverts, processus, correctifs), pas des événements. Nécessite
# WAZUH_API_HOST/PORT/USER/PASSWORD dans le .env (voir src/wazuh_inventory.py).

@app.get("/hygiene/health")
def hygiene_health() -> Dict[str, Any]:
    try:
        return wazuh_test_connection()
    except WazuhApiError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/hygiene/agents")
def hygiene_agents() -> List[Dict[str, Any]]:
    try:
        return list_agents()
    except WazuhApiError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/hygiene/overview")
def hygiene_overview() -> List[Dict[str, Any]]:
    """
    Un score d'hygiène par agent (voir wazuh_inventory.compute_hygiene_score), triés du plus
    au moins exposé. Fait 1 + 3 appels API Wazuh par agent (ports + hotfixes + vulnerabilities) :
    acceptable pour le nombre d'agents d'un petit SOC, mais pas fait pour scaler à des centaines
    d'agents. L'appel "vulnerabilities" est optionnel : le module Vulnerability Detector n'est
    pas toujours activé côté manager (licence/version) — son indisponibilité dégrade juste le
    score vers l'heuristique seule (cve_data_available=False), ce n'est jamais une erreur 502.
    """
    try:
        agents = list_agents()
    except WazuhApiError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    overview = []
    for agent in agents:
        agent_id = agent.get("id")
        os_info = agent.get("os") or {}
        platform = os_info.get("platform") or ""
        try:
            ports = get_ports(agent_id)
        except WazuhApiError:
            ports = []
        hotfixes = get_hotfixes(agent_id)
        try:
            vulnerabilities = get_vulnerabilities(agent_id)
            vulnerabilities_available = True
        except WazuhApiError:
            vulnerabilities = []
            vulnerabilities_available = False
        scoring = compute_hygiene_score(
            platform, ports, hotfixes,
            agent_os_name=os_info.get("name") or "",
            agent_os_version=os_info.get("version") or "",
            vulnerabilities=vulnerabilities,
            vulnerabilities_available=vulnerabilities_available,
        )
        overview.append(
            {
                "agent_id": agent_id,
                "agent_name": agent.get("name"),
                "ip": agent.get("ip"),
                "os_name": (agent.get("os") or {}).get("name"),
                "os_platform": platform,
                "status": agent.get("status"),
                "last_keepalive": agent.get("lastKeepAlive"),
                **scoring,
            }
        )

    overview.sort(key=lambda a: a["score"])
    return overview


@app.get("/hygiene/agent/{agent_id}/packages")
def hygiene_packages(agent_id: str) -> List[Dict[str, Any]]:
    try:
        return get_packages(agent_id)
    except WazuhApiError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/hygiene/agent/{agent_id}/ports")
def hygiene_ports(agent_id: str) -> List[Dict[str, Any]]:
    try:
        return get_ports(agent_id)
    except WazuhApiError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/hygiene/agent/{agent_id}/processes")
def hygiene_processes(agent_id: str) -> List[Dict[str, Any]]:
    try:
        return get_processes(agent_id)
    except WazuhApiError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/hygiene/agent/{agent_id}/hotfixes")
def hygiene_hotfixes(agent_id: str) -> List[Dict[str, Any]]:
    return get_hotfixes(agent_id)


@app.get("/hygiene/agent/{agent_id}/vulnerabilities")
def hygiene_vulnerabilities(agent_id: str) -> List[Dict[str, Any]]:
    """CVE détaillées (Wazuh Vulnerability Detector) pour l'onglet "CVE (Wazuh)" du détail
    agent. Liste vide (pas d'erreur 502) si le module n'est pas activé côté manager — voir
    la note sur /hygiene/overview."""
    try:
        return get_vulnerabilities(agent_id)
    except WazuhApiError:
        return []


def _build_ai_prompt(payload: AiAskRequest) -> str:
    """
    Construit un prompt compact (résumé, pas un dump brut d'objets Python) : moins de tokens
    envoyés au modèle = réponse plus rapide et moins chère, et ça force le modèle à s'appuyer
    sur des faits déjà synthétisés plutôt que de devoir lui-même trier un JSON verbeux.
    """
    server_stats = stats()
    recent = list(_alert_history)[:8]

    cat_counts = {k: v for k, v in server_stats.category_counts.items() if v}
    stats_line = (
        f"total={server_stats.total} TP={server_stats.true_positive} FP={server_stats.false_positive} "
        f"taux_TP={server_stats.tp_rate:.0%} debit={server_stats.alerts_per_min}/min "
        f"confiance_moy={server_stats.avg_confidence:.0%} categories={cat_counts or 'aucune'}"
    )

    priority_counts: Dict[str, int] = {}
    for a in recent:
        p_label = a.get("priority_label")
        if p_label:
            priority_counts[p_label] = priority_counts.get(p_label, 0) + 1

    alerts_lines = "\n".join(
        f"- [{a.get('prediction')}] {a.get('rule_description')} "
        f"(agent={a.get('agent_name')}, conf={round((a.get('confidence') or 0) * 100)}%, "
        f"cat={a.get('category_label') or '—'}, priorite={a.get('priority_label') or '—'}, "
        f"repetitions={a.get('repeat_count') or 1})"
        for a in recent
    ) or "(aucune alerte pour l'instant)"

    history_text = ""
    if payload.history:
        for turn in payload.history[-4:]:
            role = "Utilisateur" if turn.get("role") == "user" else "Assistant"
            history_text += f"{role}: {turn.get('text', '')}\n"

    return (
        f"Statistiques serveur : {stats_line}\n"
        f"Répartition priorité (8 dernières alertes) : {priority_counts or 'aucune'}\n\n"
        f"Dernières alertes :\n{alerts_lines}\n\n"
        f"Historique récent :\n{history_text or '(aucun)'}\n"
        f"Question : {payload.question}"
    )


@app.post("/ai/ask", response_model=AiAskResponse)
def ai_ask(payload: AiAskRequest) -> AiAskResponse:
    """
    Assistant IA du dashboard (panneau "Assistant SOC"). Reçoit une question, un contexte
    envoyé par le frontend (snapshot des compteurs affichés) et l'historique récent de la
    conversation ; répond via Gemini 3.1 Flash Lite en s'appuyant en priorité sur les
    statistiques et l'historique d'alertes réels détenus côté serveur (plus fiables que ce
    que le client peut reconstituer depuis le DOM).
    """
    prompt = _build_ai_prompt(payload)

    from google.genai import types

    global _gemini_client
    last_error: Optional[Exception] = None
    # Réseau observé flaky sur ce LAN interne (résolutions DNS ponctuellement en échec,
    # [Errno 11001] getaddrinfo failed, même constat que pour le SMTP — voir mailer.py::
    # _resolve_host) y compris sur des process déjà démarrés depuis un moment. Un retry
    # immédiat sans délai ne laisse aucune chance au DNS de se rétablir (2 tentatives
    # dos-à-dos échouaient systématiquement ensemble) : on retente donc jusqu'à 3 fois
    # avec un court backoff entre les tentatives, sans faire attendre l'utilisateur
    # indéfiniment ni masquer une vraie panne persistante.
    _GEMINI_RETRY_DELAYS_SECONDS = [1.0, 2.0]
    attempts = 1 + len(_GEMINI_RETRY_DELAYS_SECONDS)
    for attempt in range(attempts):
        client = _get_gemini_client()
        try:
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=AI_SYSTEM_PROMPT,
                    # Réponses volontairement courtes (voir AI_SYSTEM_PROMPT) : un budget de sortie
                    # réduit accélère aussi la génération (moins de tokens à produire = plus rapide).
                    max_output_tokens=350,
                    temperature=0.3,
                ),
            )
            answer = getattr(response, "text", None) or "Je n'ai pas pu générer de réponse."
            return AiAskResponse(answer=answer)
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            _gemini_client = None  # force la réinstanciation avant la prochaine tentative
            if attempt < len(_GEMINI_RETRY_DELAYS_SECONDS):
                time.sleep(_GEMINI_RETRY_DELAYS_SECONDS[attempt])

    raise HTTPException(status_code=502, detail=f"Erreur Gemini: {last_error}")


@app.on_event("startup")
def on_startup() -> None:
    # Reprend le flux d'alertes et les compteurs là où le process précédent s'est arrêté
    # (voir src/alerts_db.py::alert_log/stats_totals et _classify ci-dessus qui y écrit à
    # chaque alerte) — un redémarrage de l'API (déploiement, crash, maintenance) ne doit pas
    # remettre le dashboard à zéro. À faire AVANT tout le reste : le dashboard peut interroger
    # /alerts/recent ou /stats dès que le process écoute, avant même la fin de cette fonction.
    persisted_stats = alerts_db.load_stats()
    if persisted_stats:
        _stats["total"] = persisted_stats["total"]
        _stats["true_positive"] = persisted_stats["true_positive"]
        _stats["false_positive"] = persisted_stats["false_positive"]
        _stats["category_counts"].update(persisted_stats.get("category_counts") or {})
        print(f"[api] Statistiques restaurées depuis data/alerts.db : {_stats['total']} alerte(s) au total.")

    restored = alerts_db.list_recent_alert_log(limit=HISTORY_MAXLEN)
    for entry in reversed(restored):  # reversed : list_recent_alert_log renvoie du plus récent
        # au plus ancien, et appendleft() inverse l'ordre — reversed() compense pour que
        # _alert_history retrouve le même ordre (plus récent en tête) qu'avant redémarrage.
        _alert_history.appendleft(entry)
        if entry.get("status") not in ("resolved", "suppressed"):
            group_key = (entry.get("rule_id"), entry.get("agent_name"))
            _active_alert_groups[group_key] = entry
        if entry.get("status") == "suppressed":
            _suppressed_keys.add((entry.get("rule_id"), entry.get("agent_name")))
    if restored:
        print(f"[api] Flux d'alertes restauré depuis data/alerts.db : {len(restored)} entrée(s).")

    bundle = _load_model()
    if bundle is None:
        print(
            f"[api] ATTENTION : modèle introuvable à {MODEL_PATH}. "
            "Lancez d'abord `python -m src.train_model` pour l'entraîner."
        )
    else:
        print(f"[api] Modèle chargé depuis {MODEL_PATH}")

    category_bundle = _load_category_model()
    if category_bundle is None:
        print(
            f"[api] INFO : modèle de catégorie introuvable à {CATEGORY_MODEL_PATH}. "
            "/predict retombera sur la classification heuristique (src/attack_category). "
            "Lancez `python -m src.train_category_model` pour activer le modèle ML."
        )
    else:
        print(f"[api] Modèle de catégorie chargé depuis {CATEGORY_MODEL_PATH}")

    if not os.environ.get("GEMINI_API_KEY"):
        print(
            "[api] INFO : GEMINI_API_KEY non définie — /ai/ask renverra une erreur 500 "
            "tant que la clé n'est pas configurée dans l'environnement."
        )

    if not os.environ.get("ADMIN_SETUP_KEY"):
        print(
            "[api] ATTENTION : ADMIN_SETUP_KEY non définie — la création de nouveaux comptes "
            "admin (/auth/register) est désactivée tant que cette variable n'est pas configurée."
        )
    smtp_host = os.environ.get("SMTP_HOST")
    if not smtp_host:
        print(
            "[api] ATTENTION : SMTP_HOST non défini — les emails de vérification/OTP ne sont "
            "PAS envoyés, seulement loggés côté serveur (mode dev uniquement, voir src/mailer.py)."
        )
    else:
        # Affiche la config SMTP réellement chargée par CE process (hors mot de passe) — sert à
        # vérifier en un coup d'œil, au démarrage, qu'un process resté ouvert depuis longtemps
        # (ou une variable d'environnement de session périmée) n'utilise pas une config SMTP
        # différente de celle actuellement écrite dans .env.
        print(
            f"[api] Config SMTP chargée : {smtp_host}:{os.environ.get('SMTP_PORT', '587')} "
            f"(user={os.environ.get('SMTP_USER') or '—'}, tls={os.environ.get('SMTP_USE_TLS', 'yes')})"
        )


# --- Dashboard statique : monté en DERNIER sur "/" pour ne jamais masquer les routes API ci-dessus ---
if DASHBOARD_DIR.exists():
    app.mount("/", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")