"""
mailer.py
=========
Envoi des emails de vérification (inscription + code OTP de connexion) via
SMTP (smtplib, stdlib — aucune dépendance externe supplémentaire).

Variables d'environnement (voir .env.example) :
    SMTP_HOST        Hôte du serveur SMTP. Si absent, l'envoi est désactivé :
                      le code est uniquement loggé côté serveur (mode dev).
    SMTP_PORT        Port TCP (défaut 587)
    SMTP_USER        Utilisateur SMTP (optionnel selon le serveur)
    SMTP_PASSWORD    Mot de passe SMTP
    SMTP_FROM        Adresse expéditrice (défaut : SMTP_USER)
    SMTP_USE_TLS     "yes" (défaut) pour STARTTLS, "no" pour connexion en clair
                      (à réserver à un relai SMTP interne de confiance)
"""

from __future__ import annotations

import logging
import os
import smtplib
import socket
import threading
import time
from email.message import EmailMessage

logger = logging.getLogger("soc-ml.mailer")

# Réutilisation de la connexion SMTP entre deux envois : sur ce réseau, l'essentiel du
# temps d'un envoi (~5s mesuré) est la connexion TCP + STARTTLS + AUTH LOGIN, pas le
# transfert du message lui-même. Garder la connexion authentifiée ouverte entre deux
# appels (tant que le serveur ne l'a pas fermée côté relai) évite de repayer ce coût à
# chaque code envoyé. `_smtp_lock` sérialise l'accès car une connexion SMTP n'est pas
# thread-safe (FastAPI exécute les routes sync dans un threadpool, plusieurs envois
# peuvent être déclenchés en parallèle par des requêtes concurrentes).
_smtp_lock = threading.Lock()
_cached_smtp: smtplib.SMTP | None = None
_cached_smtp_key: tuple[str, int] | None = None

# Dernière IP résolue avec succès pour chaque host SMTP, en secours d'une panne DNS
# transitoire (voir _resolve_host). Ce LAN a des résolutions DNS ponctuellement en
# échec ([Errno 11001] getaddrinfo failed) alors que le relai SMTP reste joignable
# par IP — sans ce cache, une panne DNS pure fait échouer l'envoi même si le réseau
# vers le serveur mail est intact.
_resolved_ip_cache: dict[str, str] = {}


def _resolve_host(host: str) -> str:
    """Résout `host` en adresse IP, avec repli sur la dernière IP connue si la
    résolution DNS échoue. Ne masque pas une vraie panne réseau : si le relai n'a
    jamais été résolu avec succès (pas d'IP en cache) ET qu'aucun secours n'est
    configuré, l'échec DNS remonte tel quel.

    Le cache est en mémoire de process : à froid (juste après un (re)démarrage,
    ex: uvicorn --reload), il est vide. Si la panne DNS est déjà en cours à ce
    moment-là, il n'y a rien à réutiliser — d'où SMTP_HOST_FALLBACK_IP (voir
    .env.example) pour couvrir aussi ce cas, en pré-renseignant une IP connue."""
    try:
        ip = socket.gethostbyname(host)
        _resolved_ip_cache[host] = ip
        return ip
    except OSError:
        cached = _resolved_ip_cache.get(host)
        if cached:
            logger.warning(
                "Résolution DNS de %s en échec, utilisation de la dernière IP connue (%s).", host, cached,
            )
            return cached
        fallback = os.environ.get("SMTP_HOST_FALLBACK_IP", "").strip()
        if fallback:
            logger.warning(
                "Résolution DNS de %s en échec et aucune IP en cache pour ce process "
                "(process récemment démarré ?) : utilisation de SMTP_HOST_FALLBACK_IP (%s).",
                host, fallback,
            )
            return fallback
        raise


def _get_smtp_connection(host: str, port: int, user: str | None, password: str | None, use_tls: bool) -> smtplib.SMTP:
    """Retourne une connexion SMTP authentifiée, réutilisée si possible.

    Doit être appelé sous `_smtp_lock`. En cas de connexion mise en cache toujours
    valide (NOOP accepté), on la réutilise directement — sinon on referme proprement
    et on en ouvre une nouvelle (comportement identique à avant, juste mis en cache).
    """
    global _cached_smtp, _cached_smtp_key

    if _cached_smtp is not None and _cached_smtp_key == (host, port):
        try:
            status, _ = _cached_smtp.noop()
            if status == 250:
                return _cached_smtp
        except Exception:
            pass
        try:
            _cached_smtp.close()
        except Exception:
            pass
        _cached_smtp = None
        _cached_smtp_key = None

    smtp = smtplib.SMTP(_resolve_host(host), port, timeout=10)
    if use_tls:
        smtp.starttls()
    if user and password:
        smtp.login(user, password)
    _cached_smtp = smtp
    _cached_smtp_key = (host, port)
    return smtp


def _drop_cached_connection() -> None:
    """Doit être appelé sous `_smtp_lock`, après un échec d'envoi sur la connexion en cache."""
    global _cached_smtp, _cached_smtp_key
    if _cached_smtp is not None:
        try:
            _cached_smtp.close()
        except Exception:
            pass
    _cached_smtp = None
    _cached_smtp_key = None

# Nombre de tentatives et délai entre elles pour les erreurs de connexion/DNS transitoires
# (OSError, ex: [Errno 11001] getaddrinfo failed). Même constat que pour le client Gemini
# (voir src/api.py::ai_ask) : le réseau de ce LAN interne a des résolutions DNS ponctuellement
# en échec, parfois pendant plus que quelques secondes, y compris sur un process déjà démarré
# depuis un moment. Le réseau/firewall n'étant pas sous notre contrôle direct (géré par l'IT),
# on absorbe ce cas côté code avec un backoff exponentiel plutôt que d'attendre un correctif
# réseau. Réglable via l'environnement sans changement de code si le pattern de panne observé
# change (SMTP_SEND_ATTEMPTS, SMTP_RETRY_BASE_DELAY, SMTP_RETRY_MAX_DELAY).
_SEND_ATTEMPTS = int(os.environ.get("SMTP_SEND_ATTEMPTS", "9"))
_RETRY_BASE_DELAY_SECONDS = float(os.environ.get("SMTP_RETRY_BASE_DELAY", "3.0"))
_RETRY_MAX_DELAY_SECONDS = float(os.environ.get("SMTP_RETRY_MAX_DELAY", "30.0"))


def _retry_delay(attempt: int) -> float:
    """Délai avant la tentative suivante (backoff exponentiel plafonné)."""
    return min(_RETRY_BASE_DELAY_SECONDS * (2 ** (attempt - 1)), _RETRY_MAX_DELAY_SECONDS)


class MailError(Exception):
    """Échec d'envoi SMTP (connexion, auth, ou serveur distant)."""


def send_email(to_addr: str, subject: str, body: str, *, attempts: int | None = None) -> None:
    """Envoie un email par SMTP.

    `attempts` permet de surcharger _SEND_ATTEMPTS : passer 1 pour une tentative
    unique, rapide, sans backoff (usage : premier essai synchrone dans une requête
    HTTP, où on ne veut pas faire attendre l'utilisateur). Le retry complet reste
    disponible en repassant par la valeur par défaut (ex: dans une tâche d'arrière-plan
    lancée après l'échec de cette tentative rapide — voir src/auth.py::_send_code).
    """
    host = os.environ.get("SMTP_HOST")
    if not host:
        # Mode dev sans serveur SMTP configuré : on logge le contenu au lieu de
        # planter, pour ne pas bloquer le développement local. À ne JAMAIS
        # laisser dans cet état en production (voir avertissement au démarrage
        # de l'API dans src/api.py).
        logger.warning(
            "SMTP_HOST non défini : email NON envoyé (mode dev, code visible dans ce log). "
            "Destinataire=%s Sujet=%s\n%s",
            to_addr, subject, body,
        )
        return

    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASSWORD")
    sender = os.environ.get("SMTP_FROM") or user or "no-reply@soc-ml-classifier.local"
    use_tls = os.environ.get("SMTP_USE_TLS", "yes").strip().lower() == "yes"

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)

    max_attempts = attempts if attempts is not None else _SEND_ATTEMPTS
    last_error: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            with _smtp_lock:
                try:
                    smtp = _get_smtp_connection(host, port, user, password, use_tls)
                    smtp.send_message(msg)
                except (smtplib.SMTPException, OSError):
                    _drop_cached_connection()
                    raise
            return
        except (smtplib.SMTPException, OSError) as exc:
            last_error = exc
            if attempt < max_attempts:
                delay = _retry_delay(attempt)
                logger.warning(
                    "Envoi SMTP à %s échoué (tentative %d/%d) : %s — nouvelle tentative dans %.0fs.",
                    to_addr, attempt, _SEND_ATTEMPTS, exc, delay,
                )
                time.sleep(delay)

    # Inclut host:port effectivement utilisés dans le message d'erreur : indispensable pour
    # diagnostiquer un cas où le processus serveur aurait chargé une configuration SMTP_HOST
    # différente de celle actuellement dans .env (variable d'environnement de session laissée
    # par un terminal, process non redémarré depuis un ancien .env, etc.) — sans ça, "getaddrinfo
    # failed" ne dit pas QUEL host a été résolu, ce qui rend ce genre de désynchronisation
    # impossible à distinguer d'une vraie panne DNS du bon host depuis les logs seuls.
    raise MailError(
        f"Envoi de l'email à {to_addr} échoué (serveur {host}:{port}) : {last_error}"
    ) from last_error


def send_verification_code(to_addr: str, code: str, purpose: str, *, attempts: int | None = None) -> None:
    if purpose == "register":
        subject = "SOC ML Classifier — Vérification de votre email"
        body = (
            f"Code de vérification pour activer votre compte admin : {code}\n\n"
            "Ce code expire dans 10 minutes. Si vous n'êtes pas à l'origine de cette "
            "inscription, ignorez cet email."
        )
    else:
        subject = "SOC ML Classifier — Code de connexion"
        body = (
            f"Code de vérification pour finaliser votre connexion : {code}\n\n"
            "Ce code expire dans 10 minutes. Si vous n'êtes pas à l'origine de cette "
            "tentative de connexion, changez votre mot de passe immédiatement."
        )
    send_email(to_addr, subject, body, attempts=attempts)
