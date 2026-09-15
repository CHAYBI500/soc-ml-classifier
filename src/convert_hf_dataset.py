"""
convert_hf_dataset.py
======================
Télécharge le dataset HuggingFace kholil-lil/wazuh-alerts (738 alertes labellisées
TP/FP) et le convertit en un CSV de features exploitable par train_model.py.

LIMITES CONNUES DE CE DATASET (à garder en tête, voir README section "Limites du dataset") :
  - Fort déséquilibre / répétition de patterns : règles firewall (id 651) et
    log rotation (id 591) très sur-représentées.
  - Méthodologie de labellisation (TP/FP) non documentée par l'auteur du dataset.
  - Faible popularité (64 téléchargements au moment de la rédaction) -> les labels
    doivent être considérés avec prudence, pas comme une vérité terrain validée.
  - Ne couvre pas nécessairement les événements Windows/WMI/Sysmon spécifiques
    au réseau cible de ce projet (agents Windows avec monitoring étendu).

CAM-LDS (Zenodo/AIT, 81 techniques MITRE ATT&CK, 7 scénarios d'attaque réels) évalué et
écarté pour l'instant : ce sont des logs bruts (Apache access log, Linux auditd), pas des
alertes Wazuh — l'intégrer demanderait de construire un pipeline de parsing dédié pour
mapper ces logs vers un format d'alerte Wazuh, et le dataset est Linux-centrique alors que
le réseau cible ici est majoritairement Windows/SQL Server. Voir README section "Limites".

Usage :
    python -m src.convert_hf_dataset --output data/processed/training_data.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

from src.attack_category import derive_category
from src.feature_engineering import build_features
from src.parse_wazuh import parse_alert
from src.seed_alerts import generate_seed_alerts

HF_DATASET_NAME = "kholil-lil/wazuh-alerts"
RULESET_CACHE_PATH = Path("data/raw/wazuh_ruleset_rules.json")


def load_hf_dataset():
    """Charge le dataset HuggingFace. Lève une erreur explicite si `datasets` n'est pas installé
    ou si le réseau n'est pas disponible (fallback expliqué à l'utilisateur)."""
    try:
        from datasets import load_dataset
    except ImportError as e:
        raise ImportError(
            "Le package 'datasets' est requis pour ce script. "
            "Installez-le via `pip install datasets` (déjà présent dans requirements.txt)."
        ) from e

    print(f"[convert_hf_dataset] Téléchargement de {HF_DATASET_NAME} depuis HuggingFace Hub...")
    ds = load_dataset(HF_DATASET_NAME)
    # La plupart des petits datasets HF n'ont qu'un split "train"
    split = "train" if "train" in ds else list(ds.keys())[0]
    return ds[split]


def _guess_label(row: dict) -> int:
    """
    Normalise le label du dataset HF vers 1 (True Positive) / 0 (False Positive).

    Schéma RÉEL de kholil-lil/wazuh-alerts (vérifié sur la fiche dataset HF, format
    instruction-tuning à 3 colonnes) :
        instruction : "Classify the following Wazuh alert as a true positive or false positive."
        input       : chaîne JSON de l'alerte Wazuh brute (rule.id, rule.level, rule.groups, ...)
        output      : "True Positive" ou "False Positive" (texte libre)

    On gère quand même quelques variantes de casse/format en fallback, au cas où
    l'auteur ferait évoluer le schéma dans une future version du dataset.
    """
    for key in ("output", "label", "classification", "verdict", "is_true_positive"):
        if key in row and row[key] is not None:
            val = row[key]
            if isinstance(val, bool):
                return int(val)
            if isinstance(val, (int, float)):
                return int(val)
            val_str = str(val).strip().lower()
            if val_str in ("true positive", "tp", "true_positive", "1", "malicious", "attack"):
                return 1
            if val_str in ("false positive", "fp", "false_positive", "0", "benign", "noise"):
                return 0
    raise KeyError(
        "Impossible de déterminer le label TP/FP pour une ligne du dataset. "
        "Vérifiez le schéma exact de kholil-lil/wazuh-alerts et adaptez _guess_label()."
    )


def convert(output_path: str) -> None:
    import json as _json

    hf_rows = load_hf_dataset()

    records = []
    labels = []
    categories = []
    skipped = 0

    for row in hf_rows:
        row = dict(row)

        # Schéma réel : la colonne 'input' contient l'alerte Wazuh brute en JSON (string).
        raw_alert = row.get("input")

        if raw_alert is None:
            # Fallback : anciennes variantes possibles de nommage de colonne
            for key in ("alert", "raw_json", "raw_alert", "json"):
                if key in row and row[key]:
                    raw_alert = row[key]
                    break

        if raw_alert is None:
            # Dernier recours : reconstruire un pseudo-JSON Wazuh depuis des colonnes à plat
            raw_alert = {
                "rule": {
                    "id": row.get("rule_id", row.get("rule.id", "0")),
                    "level": row.get("rule_level", row.get("rule.level", 0)),
                    "description": row.get("rule_description", row.get("rule.description", "")),
                    "groups": row.get("rule_groups", row.get("rule.groups", [])),
                },
                "agent": {
                    "id": row.get("agent_id", "000"),
                    "name": row.get("agent_name", "unknown"),
                },
                "data": {
                    "srcip": row.get("srcip"),
                    "dstip": row.get("dstip"),
                },
                "timestamp": row.get("timestamp"),
            }

        if isinstance(raw_alert, str):
            try:
                raw_alert = _json.loads(raw_alert)
            except _json.JSONDecodeError:
                skipped += 1
                continue

        parsed = parse_alert(raw_alert)
        if parsed is None:
            skipped += 1
            continue

        try:
            label = _guess_label(row)
        except KeyError:
            skipped += 1
            continue

        records.append(parsed)
        labels.append(label)
        categories.append(derive_category(parsed))

    hf_count = len(records)

    # Complète le dataset public avec des alertes synthétiques (mais basées sur des règles
    # Wazuh réelles/plausibles) pour les catégories absentes de kholil-lil/wazuh-alerts
    # (malware, recon, endpoint, network) et pour renforcer "sql" — voir src/seed_alerts.py.
    seed_count = 0
    for seed in generate_seed_alerts():
        parsed = parse_alert(seed["raw"])
        if parsed is None:
            continue
        records.append(parsed)
        labels.append(seed["label"])
        categories.append(derive_category(parsed))
        seed_count += 1

    # Complète encore avec des alertes générées à partir du VRAI ruleset officiel Wazuh
    # (rule.id/level/description/groups/MITRE authentiques, voir src/fetch_wazuh_ruleset.py
    # pour la méthodologie d'extraction et de labellisation, et pour la justification du choix
    # de cette source plutôt que d'autres datasets HuggingFace évalués et écartés). Optionnel :
    # si data/raw/wazuh_ruleset_rules.json n'existe pas encore, exécuter d'abord
    # `python -m src.fetch_wazuh_ruleset`.
    ruleset_count = 0
    if RULESET_CACHE_PATH.exists():
        from src.fetch_wazuh_ruleset import generate_ruleset_alerts

        cached_rules = _json.loads(RULESET_CACHE_PATH.read_text(encoding="utf-8"))
        for entry in generate_ruleset_alerts(cached_rules):
            parsed = parse_alert(entry["raw"])
            if parsed is None:
                continue
            records.append(parsed)
            labels.append(entry["label"])
            categories.append(derive_category(parsed))
            ruleset_count += 1
    else:
        print(
            f"[convert_hf_dataset] INFO : {RULESET_CACHE_PATH} absent, source ruleset Wazuh "
            "ignorée. Lancer `python -m src.fetch_wazuh_ruleset` pour l'activer."
        )

    if not records:
        print(
            "[convert_hf_dataset] ERREUR : aucun enregistrement exploitable n'a été extrait. "
            "Le schéma du dataset HF a probablement changé — inspectez une ligne brute "
            "(ds['train'][0]) et adaptez convert() en conséquence.",
            file=sys.stderr,
        )
        sys.exit(1)

    features_df = build_features(records)
    features_df["label"] = labels
    features_df["category"] = categories

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    features_df.to_csv(out, index=False)

    tp_count = sum(labels)
    fp_count = len(labels) - tp_count
    print(f"[convert_hf_dataset] {len(records)} alertes au total : {hf_count} de kholil-lil/wazuh-alerts + {seed_count} synthétiques (src/seed_alerts.py) + {ruleset_count} issues du ruleset officiel Wazuh (src/fetch_wazuh_ruleset.py), {skipped} ignorées.")
    print(f"[convert_hf_dataset] Répartition labels : TP={tp_count}, FP={fp_count}")
    print(f"[convert_hf_dataset] Répartition catégories :\n{pd.Series(categories).value_counts()}")
    print(f"[convert_hf_dataset] CSV écrit dans {out}")
    print(
        "[convert_hf_dataset] RAPPEL : dataset de 738 alertes avec forte répétition de patterns "
        "(règles firewall/log-rotation), méthodologie de labellisation non documentée. "
        "À utiliser avec prudence, cf. README section 'Limites du dataset'."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convertit kholil-lil/wazuh-alerts en CSV de features.")
    parser.add_argument(
        "--output",
        default="data/processed/training_data.csv",
        help="Chemin du CSV de sortie (défaut: data/processed/training_data.csv)",
    )
    args = parser.parse_args()
    convert(args.output)
