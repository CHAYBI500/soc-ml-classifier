"""
security.py
============
Primitives de sécurité pour l'authentification admin. Volontairement sans
dépendance externe (tout est stdlib : hashlib, hmac, secrets) :
    - hachage de mot de passe (scrypt, avec sel aléatoire par utilisateur)
    - génération de jetons de session opaques et de codes de vérification email
    - comparaisons en temps constant (évite les attaques par timing)

Aucun mot de passe ni code en clair n'est jamais stocké : seul le hash va en
base (voir src/auth_db.py).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import string

# Paramètres scrypt (N, r, p) : compromis coût CPU/mémoire raisonnable pour un
# login admin peu fréquent (pas un service à fort trafic). N=2^14 ~ 16 Mo de
# mémoire par hash, quelques dizaines de ms sur un poste récent.
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SCRYPT_SALT_BYTES = 16

EMAIL_CODE_LENGTH = 6


def hash_password(password: str) -> str:
    """Hash un mot de passe avec un sel aléatoire. Format stocké :
    "scrypt$N$r$p$sel_hex$hash_hex" (auto-descriptif, permet de faire évoluer
    les paramètres plus tard sans invalider les hash existants)."""
    salt = os.urandom(SCRYPT_SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Vérifie un mot de passe contre un hash stocké. Retourne False (jamais
    d'exception) sur un format invalide, pour ne jamais faire planter le login."""
    try:
        scheme, n_s, r_s, p_s, salt_hex, digest_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        n, r, p = int(n_s), int(r_s), int(p_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, AttributeError):
        return False

    candidate = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected))
    return hmac.compare_digest(candidate, expected)


def generate_session_token() -> str:
    """Jeton de session opaque (128 bits d'entropie), envoyé au client via cookie.
    Seul son hash SHA-256 est stocké en base (voir hash_token) : un vol de la
    base ne permet donc pas de rejouer une session existante."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_email_code() -> str:
    """Code numérique à 6 chiffres pour la vérification email / 2FA login."""
    return "".join(secrets.choice(string.digits) for _ in range(EMAIL_CODE_LENGTH))


def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def constant_time_eq(a: str, b: str) -> bool:
    """Compare deux chaînes en temps constant. Encode en UTF-8 avant de comparer :
    hmac.compare_digest() refuse de comparer des `str` contenant des caractères
    non-ASCII (lève TypeError), alors qu'il accepte n'importe quel contenu en `bytes`.
    Une clé d'installation ou un code saisis par un utilisateur peuvent contenir
    n'importe quel caractère (copier-coller, clavier non-US, etc.), donc cette
    fonction doit rester utilisable dans tous les cas plutôt que de planter en 500."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
