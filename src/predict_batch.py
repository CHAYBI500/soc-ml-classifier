"""
predict_batch.py
=================
Inférence en masse sur un fichier d'alertes Wazuh (alerts.json), sans passer par l'API.
Utile pour tester le modèle sur un lot d'alertes historiques ou pour un audit hors-ligne.

Usage :
    python -m src.predict_batch --model models/rf_classifier.joblib --input data/raw/alerts.json --output data/processed/predictions.csv
"""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd

from src.feature_engineering import build_features
from src.parse_wazuh import parse_file


def predict_batch(model_path: str, input_path: str, output_path: str, threshold: float = 0.5) -> pd.DataFrame:
    bundle = joblib.load(model_path)
    clf = bundle["model"]
    feature_columns = bundle["feature_columns"]

    records = parse_file(input_path)
    if not records:
        print("[predict_batch] Aucune alerte exploitable trouvée dans le fichier d'entrée.")
        return pd.DataFrame()

    features_df = build_features(records)
    X = features_df[feature_columns].fillna(0)

    proba = clf.predict_proba(X)[:, 1]  # probabilité de la classe True Positive
    prediction = (proba >= threshold).astype(int)

    result = pd.DataFrame(
        {
            "rule_id": features_df.get("_meta_rule_id"),
            "rule_description": features_df.get("_meta_rule_description"),
            "agent_name": features_df.get("_meta_agent_name"),
            "confidence": proba.round(4),
            "prediction": ["True Positive" if p == 1 else "False Positive" for p in prediction],
        }
    )

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(out, index=False)

    tp = int(prediction.sum())
    fp = len(prediction) - tp
    print(f"[predict_batch] {len(result)} alertes traitées : {tp} True Positive, {fp} False Positive")
    print(f"[predict_batch] Résultats écrits dans {out}")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Inférence en masse sur un lot d'alertes Wazuh.")
    parser.add_argument("--model", default="models/rf_classifier.joblib")
    parser.add_argument("--input", default="data/raw/alerts.json")
    parser.add_argument("--output", default="data/processed/predictions.csv")
    parser.add_argument("--threshold", type=float, default=0.5, help="Seuil de confiance pour classer en True Positive")
    args = parser.parse_args()

    predict_batch(args.model, args.input, args.output, threshold=args.threshold)
