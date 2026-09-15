"""
train_model.py
===============
Entraîne un RandomForestClassifier (scikit-learn) pour classifier les alertes
Wazuh en True Positive (1) / False Positive (0).

Pourquoi Random Forest plutôt qu'un LLM ou du deep learning ? (voir README section 6)
  - Données tabulaires structurées : un ensemble d'arbres est généralement plus
    performant qu'un réseau de neurones profond sur ce type de features.
  - Latence en millisecondes, critique pour un triage temps réel (un appel LLM
    par alerte serait trop lent et trop coûteux à l'échelle d'un SOC).
  - Interprétable via feature_importances_, ce qui est justifiable auprès d'un
    analyste SOC ou d'un auditeur (contrairement à une boîte noire).
  - Robuste au bruit et aux features corrélées (fréquentes ici : rule_level et
    les flags de groupe sont partiellement redondants).
  - Cohérent avec la littérature publiée sur l'intégration ML/Wazuh, qui rapporte
    des précisions de l'ordre de ~97% avec Random Forest sur des tâches similaires.

Usage :
    python -m src.train_model --data data/processed/training_data.csv --output models/rf_classifier.joblib
"""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split

from src.feature_engineering import FEATURE_COLUMNS


def train(data_path: str, output_path: str, test_size: float = 0.2, random_state: int = 42) -> None:
    df = pd.read_csv(data_path)

    if "label" not in df.columns:
        raise ValueError("Le CSV d'entraînement doit contenir une colonne 'label' (0=FP, 1=TP).")

    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Colonnes de features manquantes dans le CSV : {missing}")

    X = df[FEATURE_COLUMNS].fillna(0)
    y = df["label"].astype(int)

    print(f"[train_model] Dataset : {len(df)} lignes, répartition labels :\n{y.value_counts()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y if y.nunique() > 1 else None
    )

    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("\n[train_model] Rapport de classification (jeu de test, split unique 80/20) :")
    print(classification_report(y_test, y_pred, target_names=["False Positive", "True Positive"]))
    print("[train_model] Matrice de confusion :")
    print(confusion_matrix(y_test, y_pred))

    # Un seul split 80/20 donne une estimation bruitée (dépend du tirage aléatoire). On ajoute
    # une validation croisée stratifiée 5-fold sur l'intégralité des données pour une estimation
    # plus robuste (moyenne + écart-type sur 5 découpages différents) — n'affecte PAS le modèle
    # sauvegardé (toujours celui entraîné sur X_train ci-dessus, comportement inchangé).
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=random_state)
    cv_results = cross_validate(
        clone(clf), X, y, cv=cv,
        scoring=["accuracy", "f1_macro", "precision_macro", "recall_macro"],
    )
    print("\n[train_model] Validation croisée stratifiée (5-fold, sur l'ensemble du dataset) :")
    for metric in ["accuracy", "f1_macro", "precision_macro", "recall_macro"]:
        scores = cv_results[f"test_{metric}"]
        print(f"  {metric:<18} {scores.mean():.4f} ± {scores.std():.4f}  (folds: {np.round(scores, 4).tolist()})")

    importances = sorted(
        zip(FEATURE_COLUMNS, clf.feature_importances_), key=lambda x: x[1], reverse=True
    )
    print("\n[train_model] Top features (importance décroissante) :")
    for name, imp in importances[:12]:
        print(f"  {name:<30} {imp:.4f}")

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": clf, "feature_columns": FEATURE_COLUMNS}, out)
    print(f"\n[train_model] Modèle sauvegardé dans {out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Entraîne le classifieur RandomForest TP/FP.")
    parser.add_argument("--data", default="data/processed/training_data.csv", help="CSV de features labellisées")
    parser.add_argument("--output", default="models/rf_classifier.joblib", help="Chemin de sauvegarde du modèle")
    parser.add_argument("--test-size", type=float, default=0.2)
    args = parser.parse_args()

    train(args.data, args.output, test_size=args.test_size)
