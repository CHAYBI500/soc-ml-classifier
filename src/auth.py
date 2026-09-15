"""
auth.py
=======
Authentification admin du dashboard : inscription (verrouillée par une clé
d'installation partagée), vérification d'email, connexion en deux temps
(mot de passe puis code OTP envoyé par email), sessions par cookie, et
historique des connexions (email, nom, machine).

Endpoints :
    POST /auth/register        -> crée un compte admin (nécessite setup_key), envoie un code email
    POST /auth/verify-email    -> confirme l'email avec le code reçu (active le compte)
    POST /auth/resend-code     -> renvoie un code (register ou login), avec cooldown anti-spam
    POST /auth/login           -> étape 1 : email + mot de passe -> envoie un code OTP par email
    POST /auth/login/verify    -> étape 2 : email + code OTP -> ouvre la session (cookie)
    POST /auth/logout          -> révoque la session courante
    GET  /auth/me              -> identité de l'admin actuellement authentifié
    GET  /auth/history         -> historique des connexions (admin authentifié uniquement)

Sécurité :
    - Mots de passe hashés avec sel (scrypt, voir src/security.py), jamais stockés en clair.
    - Double facteur : mot de passe + code à usage unique envoyé par email, expirant,
      à tentatives limitées.
    - Anti brute-force : verrouillage temporaire par couple (email) ET (IP) après
      plusieurs échecs, sur la connexion ET la vérification OTP.
    - Jeton de session opaque (aucune donnée décodable côté client) ; seul son hash
      SHA-256 est stocké en base (voir src/auth_db.py) — un vol de la base ne permet
      pas de rejouer une session.
    - Historique de connexion : email, nom, IP, user-agent et nom de machine
      (résolu par DNS inverse côté serveur à partir de l'IP source — un navigateur
      ne permettant pas de lire le hostname OS pour des raisons de vie privée).
"""

from __future__ import annotations

import logging
import os
import re
import socket
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response
from pydantic import BaseModel, Field

from src import auth_db, security
from src.mailer import MailError, send_verification_code

logger = logging.getLogger("soc-ml.auth")

router = APIRouter(prefix="/auth", tags=["auth"])

# --- Configuration -------------------------------------------------------------

SESSION_COOKIE_NAME = "soc_admin_session"
SESSION_TTL_HOURS = int(os.environ.get("ADMIN_SESSION_TTL_HOURS", "8"))
EMAIL_CODE_TTL_MINUTES = 10
MAX_CODE_ATTEMPTS = 5
RESEND_COOLDOWN_SECONDS = 30

# Anti brute-force : verrouillage après ce nombre d'échecs (mot de passe OU code
# OTP confondus), par couple email/IP, pour la durée indiquée.
LOCKOUT_THRESHOLD = 5
LOCKOUT_MINUTES = 15

COOKIE_SECURE = os.environ.get("ADMIN_COOKIE_SECURE", "no").strip().lower() == "yes"

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

auth_db.init_db()


# --- Schémas ---------------------------------------------------------------

class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: str
    password: str
    setup_key: str


class VerifyEmailRequest(BaseModel):
    email: str
    code: str


class ResendCodeRequest(BaseModel):
    email: str
    purpose: str  # "register" ou "login"


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginVerifyRequest(BaseModel):
    email: str
    code: str


# --- Aides -------------------------------------------------------------------

def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _resolve_machine_name(ip: str) -> Optional[str]:
    """Résolution DNS inverse best-effort du nom de machine à partir de l'IP
    source. Fiable sur un LAN interne avec DNS/AD déjà en place (cas de ce SOC,
    réseau 172.17.1.0/24) ; retourne None si la résolution échoue ou prend trop
    de temps (timeout court pour ne jamais bloquer le login)."""
    try:
        socket.setdefaulttimeout(3.0)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError, ValueError):
        return None
    finally:
        socket.setdefaulttimeout(None)


def _validate_email(email: str) -> str:
    email = email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Adresse email invalide.")
    return email


def _validate_password_strength(password: str) -> None:
    if len(password) < 10:
        raise HTTPException(status_code=400, detail="Le mot de passe doit contenir au moins 10 caractères.")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise HTTPException(
            status_code=400, detail="Le mot de passe doit contenir au moins une lettre et un chiffre."
        )


def _throttle_keys(email: str, ip: str) -> tuple[str, str]:
    return f"email:{email}", f"ip:{ip}"


def _check_locked(email: str, ip: str) -> None:
    for key in _throttle_keys(email, ip):
        row = auth_db.get_throttle(key)
        if row and row["locked_until"] and row["locked_until"] > auth_db.now_iso():
            raise HTTPException(
                status_code=429,
                detail=(
                    "Trop de tentatives échouées. Réessayez après un court délai "
                    f"(verrouillé jusqu'à {row['locked_until']})."
                ),
            )


def _register_failure(email: str, ip: str) -> None:
    for key in _throttle_keys(email, ip):
        auth_db.register_failed_attempt(key, LOCKOUT_THRESHOLD, LOCKOUT_MINUTES)


def _reset_throttle(email: str, ip: str) -> None:
    for key in _throttle_keys(email, ip):
        auth_db.reset_throttle(key)


def get_admin_from_request(request: Request) -> Optional[Dict[str, Any]]:
    """Résout l'admin authentifié à partir du cookie de session, ou None.
    Utilisé par le middleware global (src/api.py) et par /auth/me."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    session = auth_db.get_active_session_by_token_hash(security.hash_token(token))
    if not session:
        return None
    admin = auth_db.get_admin_by_id(session["admin_id"])
    if not admin or not admin["is_active"] or not admin["is_email_verified"]:
        return None
    return admin


def _send_code(background_tasks: BackgroundTasks, email: str, code: str, purpose: str) -> None:
    """Envoie le code par email. Une seule tentative rapide est faite dans la requête
    HTTP elle-même (pas de backoff ici : on ne veut pas faire attendre l'utilisateur
    plusieurs dizaines de secondes sur un bouton). En cas d'échec de cette tentative
    rapide — typiquement une panne DNS/réseau transitoire côté LAN, hors de notre
    contrôle direct (voir src/mailer.py) — le renvoi complet avec backoff est délégué
    à une tâche d'arrière-plan : la requête répond normalement sans attendre, et
    l'email arrive dès que le réseau redevient joignable dans la fenêtre de retry.
    Si la tentative rapide échoue pour une raison non transitoire (identifiants SMTP
    invalides, SMTP_HOST absent, etc.), la tâche d'arrière-plan échouera aussi de la
    même façon ; c'est journalisé (logger.error) pour un diagnostic côté ops plutôt
    que remonté en 502 au client, qui n'a de toute façon aucune action à faire dessus."""
    try:
        send_verification_code(email, code, purpose, attempts=1)
    except MailError as exc:
        logger.warning(
            "Envoi immédiat du code (%s) à %s échoué : %s — nouvelle tentative en arrière-plan.",
            purpose, email, exc,
        )
        background_tasks.add_task(_send_code_background, email, code, purpose)


def _send_code_background(email: str, code: str, purpose: str) -> None:
    try:
        send_verification_code(email, code, purpose)
    except MailError as exc:
        logger.error("Échec définitif de l'envoi du code (%s) à %s : %s", purpose, email, exc)


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=SESSION_TTL_HOURS * 3600,
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
        path="/",
    )


# --- Endpoints -----------------------------------------------------------------

@router.post("/register")
def register(payload: RegisterRequest, background_tasks: BackgroundTasks) -> Dict[str, str]:
    expected_key = os.environ.get("ADMIN_SETUP_KEY")
    if not expected_key:
        raise HTTPException(
            status_code=503,
            detail="ADMIN_SETUP_KEY non configurée côté serveur : inscription admin désactivée.",
        )
    if not security.constant_time_eq(payload.setup_key, expected_key):
        raise HTTPException(status_code=403, detail="Clé d'installation invalide.")

    email = _validate_email(payload.email)
    _validate_password_strength(payload.password)

    password_hash = security.hash_password(payload.password)
    existing = auth_db.get_admin_by_email(email)

    if existing:
        if existing["is_email_verified"]:
            raise HTTPException(status_code=409, detail="Un compte existe déjà avec cet email.")
        # Compte créé lors d'une précédente tentative mais jamais activé (ex: échec
        # d'envoi de l'email) : ce n'est pas un vrai conflit, on relance simplement
        # l'inscription (nouveau mot de passe pris en compte, nouveau code envoyé),
        # avec le même cooldown anti-spam que /auth/resend-code.
        existing_code = auth_db.get_latest_active_code(existing["id"], "register")
        if existing_code:
            elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(existing_code["created_at"])).total_seconds()
            if elapsed < RESEND_COOLDOWN_SECONDS:
                retry_after = int(RESEND_COOLDOWN_SECONDS - elapsed)
                raise HTTPException(
                    status_code=429,
                    detail=f"Un code a déjà été envoyé. Merci de patienter {retry_after}s avant d'en redemander un.",
                    headers={"Retry-After": str(retry_after)},
                )
        auth_db.update_pending_admin(existing["id"], payload.name.strip(), password_hash)
        admin_id = existing["id"]
    else:
        admin_id = auth_db.create_admin(payload.name.strip(), email, password_hash)

    code = security.generate_email_code()
    auth_db.create_email_code(admin_id, "register", security.hash_code(code), EMAIL_CODE_TTL_MINUTES)
    _send_code(background_tasks, email, code, "register")

    return {"status": "pending_verification"}


@router.post("/verify-email")
def verify_email(payload: VerifyEmailRequest) -> Dict[str, str]:
    email = _validate_email(payload.email)
    admin = auth_db.get_admin_by_email(email)
    generic_error = HTTPException(status_code=400, detail="Code invalide ou expiré.")
    if not admin:
        raise generic_error

    code_row = auth_db.get_latest_active_code(admin["id"], "register")
    if not code_row or code_row["expires_at"] < auth_db.now_iso():
        raise generic_error
    if code_row["attempts"] >= MAX_CODE_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Trop de tentatives, demandez un nouveau code.")

    if not security.constant_time_eq(security.hash_code(payload.code.strip()), code_row["code_hash"]):
        auth_db.increment_code_attempts(code_row["id"])
        raise generic_error

    auth_db.consume_code(code_row["id"])
    auth_db.set_email_verified(admin["id"])
    return {"status": "verified"}


@router.post("/resend-code")
def resend_code(payload: ResendCodeRequest, background_tasks: BackgroundTasks) -> Dict[str, str]:
    if payload.purpose not in ("register", "login"):
        raise HTTPException(status_code=400, detail="Paramètre purpose invalide.")

    email = _validate_email(payload.email)
    admin = auth_db.get_admin_by_email(email)
    # Réponse générique que l'admin existe ou non, pour ne pas permettre l'énumération de comptes.
    generic_response = {"status": "sent_if_account_exists"}
    if not admin:
        return generic_response

    existing = auth_db.get_latest_active_code(admin["id"], payload.purpose)
    if existing:
        created = datetime.fromisoformat(existing["created_at"])
        elapsed = (datetime.now(timezone.utc) - created).total_seconds()
        if elapsed < RESEND_COOLDOWN_SECONDS:
            retry_after = int(RESEND_COOLDOWN_SECONDS - elapsed)
            raise HTTPException(
                status_code=429,
                detail=f"Un code a déjà été envoyé. Merci de patienter {retry_after}s avant d'en redemander un.",
                headers={"Retry-After": str(retry_after)},
            )

    code = security.generate_email_code()
    auth_db.create_email_code(admin["id"], payload.purpose, security.hash_code(code), EMAIL_CODE_TTL_MINUTES)
    _send_code(background_tasks, email, code, payload.purpose)
    return generic_response


@router.post("/login")
def login(payload: LoginRequest, request: Request, background_tasks: BackgroundTasks) -> Dict[str, str]:
    ip = _client_ip(request)
    email = _validate_email(payload.email)

    _check_locked(email, ip)

    admin = auth_db.get_admin_by_email(email)
    invalid = HTTPException(status_code=401, detail="Identifiants invalides.")

    if not admin or not admin["is_active"] or not security.verify_password(payload.password, admin["password_hash"]):
        _register_failure(email, ip)
        auth_db.record_login_history(
            admin["id"] if admin else None, email, admin["name"] if admin else None,
            ip, _resolve_machine_name(ip), request.headers.get("user-agent"), False, "mot de passe invalide",
        )
        raise invalid

    if not admin["is_email_verified"]:
        raise HTTPException(status_code=403, detail="Email non vérifié. Consultez votre boîte mail pour activer le compte.")

    code = security.generate_email_code()
    auth_db.create_email_code(admin["id"], "login", security.hash_code(code), EMAIL_CODE_TTL_MINUTES)
    _send_code(background_tasks, email, code, "login")
    return {"status": "otp_required"}


@router.post("/login/verify")
def login_verify(payload: LoginVerifyRequest, request: Request, response: Response) -> Dict[str, Any]:
    ip = _client_ip(request)
    email = _validate_email(payload.email)
    user_agent = request.headers.get("user-agent")

    _check_locked(email, ip)

    admin = auth_db.get_admin_by_email(email)
    invalid = HTTPException(status_code=401, detail="Code invalide ou expiré.")
    if not admin:
        _register_failure(email, ip)
        raise invalid

    machine_name = _resolve_machine_name(ip)

    code_row = auth_db.get_latest_active_code(admin["id"], "login")
    if not code_row or code_row["expires_at"] < auth_db.now_iso():
        _register_failure(email, ip)
        auth_db.record_login_history(admin["id"], email, admin["name"], ip, machine_name, user_agent, False, "code OTP expiré")
        raise invalid
    if code_row["attempts"] >= MAX_CODE_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Trop de tentatives, redemandez un code.")

    if not security.constant_time_eq(security.hash_code(payload.code.strip()), code_row["code_hash"]):
        auth_db.increment_code_attempts(code_row["id"])
        _register_failure(email, ip)
        auth_db.record_login_history(admin["id"], email, admin["name"], ip, machine_name, user_agent, False, "code OTP invalide")
        raise invalid

    auth_db.consume_code(code_row["id"])
    _reset_throttle(email, ip)

    token = security.generate_session_token()
    auth_db.create_session(admin["id"], security.hash_token(token), SESSION_TTL_HOURS, ip, machine_name, user_agent)
    auth_db.record_login_history(admin["id"], email, admin["name"], ip, machine_name, user_agent, True, "connexion réussie")

    _set_session_cookie(response, token)
    return {"status": "ok", "name": admin["name"], "email": admin["email"]}


@router.post("/logout")
def logout(request: Request, response: Response) -> Dict[str, str]:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        auth_db.revoke_session(security.hash_token(token))
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"status": "logged_out"}


@router.get("/me")
def me(request: Request) -> Dict[str, Any]:
    admin = get_admin_from_request(request)
    if not admin:
        raise HTTPException(status_code=401, detail="Non authentifié.")
    return {"name": admin["name"], "email": admin["email"]}


@router.get("/history")
def history(request: Request, limit: int = 50) -> list:
    if not get_admin_from_request(request):
        raise HTTPException(status_code=401, detail="Non authentifié.")
    limit = max(1, min(limit, 200))
    return auth_db.list_login_history(limit)
