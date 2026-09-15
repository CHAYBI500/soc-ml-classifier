#!/var/ossec/framework/python/bin/python3
"""
custom-ml-triage.py
====================
Intégration custom Wazuh : envoie chaque alerte (niveau >= 3, cf. ossec.conf)
vers l'API ML soc-ml-classifier pour un triage TP/FP en temps réel.

Cohérent avec le style de /var/ossec/integrations/custom-abuseipdb.py déjà en place :
  - RotatingFileHandler pour le logging
  - retry/backoff sur les appels réseau
  - lecture d'UNE alerte JSON unique (le fichier passé en argument par Wazuh),
    contrairement à predict_batch.py qui traite un fichier alerts.json complet.

Invocation par Wazuh (via le wrapper shell custom-ml-triage) :
    custom-ml-triage.py <alert_file> <api_key_placeholder> [<hook_url>]

  <alert_file>        : chemin vers un fichier contenant UNE alerte JSON
                         (fourni automatiquement par integrator)
  <api_key_placeholder>: argument positionnel standard des intégrations Wazuh,
                         non utilisé ici (l'API ML ne requiert pas de clé)
  <hook_url>           : optionnel, surcharge API_URL par défaut
                         (doit correspondre au <hook_url> de ossec.conf)

Configuration associée dans ossec.conf du manager (10.212.2.170) :
    <integration>
      <name>custom-ml-triage</name>
      <hook_url>http://172.17.1.120:8000/predict</hook_url>
      <alert_format>json</alert_format>
      <level>3</level>
    </integration>
"""

import json
import logging
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

import requests

# --- Configuration ---------------------------------------------------------

API_URL_DEFAULT = "http://172.17.1.120:8000/predict"
LOG_FILE = "/var/ossec/logs/integrations/custom-ml-triage.log"
LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 Mo, cohérent avec custom-abuseipdb
LOG_BACKUP_COUNT = 3

REQUEST_TIMEOUT = 5  # secondes
MAX_RETRIES = 3
BACKOFF_BASE = 2  # secondes : 2s, 4s, 8s

# --- Logging -----------------------------------------------------------------

logger = logging.getLogger("custom-ml-triage")
logger.setLevel(logging.INFO)

try:
    Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
    _handler = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT)
except (OSError, PermissionError):
    # Fallback stderr si /var/ossec/logs/integrations n'est pas accessible en écriture
    # (ex: exécution manuelle hors contexte Wazuh pour test)
    _handler = logging.StreamHandler(sys.stderr)

_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logger.addHandler(_handler)


def read_alert(alert_file_path: str) -> dict:
    """Lit et parse le fichier d'alerte JSON unique fourni par Wazuh."""
    with open(alert_file_path, "r", encoding="utf-8", errors="replace") as f:
        return json.load(f)


def call_ml_api(alert: dict, api_url: str) -> dict:
    """
    Envoie l'alerte à l'API ML avec retry/backoff exponentiel.
    Cohérent avec la logique de résilience de custom-abuseipdb.py.
    """
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.post(api_url, json=alert, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            last_error = e
            logger.warning(
                "Tentative %d/%d échouée pour %s : %s", attempt, MAX_RETRIES, api_url, e
            )
            if attempt < MAX_RETRIES:
                sleep_time = BACKOFF_BASE ** attempt
                time.sleep(sleep_time)

    raise RuntimeError(f"Échec après {MAX_RETRIES} tentatives : {last_error}")


def main():
    if len(sys.argv) < 2:
        logger.error("Arguments manquants. Usage: custom-ml-triage.py <alert_file> <api_key> [<hook_url>]")
        sys.exit(1)

    alert_file = sys.argv[1]
    # sys.argv[2] est le placeholder de clé API standard des intégrations Wazuh, non utilisé ici.
    api_url = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else API_URL_DEFAULT

    try:
        alert = read_alert(alert_file)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Impossible de lire/parser le fichier d'alerte %s : %s", alert_file, e)
        sys.exit(1)

    rule_id = alert.get("rule", {}).get("id", "unknown")
    rule_level = alert.get("rule", {}).get("level", "unknown")

    try:
        result = call_ml_api(alert, api_url)
    except RuntimeError as e:
        logger.error("Échec de l'appel API ML pour rule.id=%s (level=%s) : %s", rule_id, rule_level, e)
        sys.exit(1)

    prediction = result.get("prediction", "unknown")
    confidence = result.get("confidence", 0.0)

    logger.info(
        "rule.id=%s level=%s -> prediction=%s confidence=%.4f",
        rule_id, rule_level, prediction, confidence,
    )

    # NOTE : conformément à la contrainte du projet, ce script n'effectue AUCUN
    # blocage automatique. Il journalise uniquement le verdict ML. Les actions
    # (blocage pfSense, ticket GLPI, notification Telegram) restent pilotées par
    # le flux n8n SOAR existant, en aval, sur la base des alertes de niveau >= 12.

    sys.exit(0)


if __name__ == "__main__":
    main()
