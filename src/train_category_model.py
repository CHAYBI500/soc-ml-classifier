"""
train_category_model.py
========================
Entraîne un second RandomForestClassifier, multi-classe, qui prédit la CATÉGORIE de
menace/incident (sql, malware, bruteforce, recon, web, endpoint, network, other) en
complément — et non en remplacement — du classifieur binaire True Positive/False Positive
existant (train_model.py). Les deux modèles sont indépendants et chargés séparément par
l'API (/predict renvoie "prediction"/"confidence" ET "category"/"category_confidence").

Pourquoi un second modèle plutôt qu'une seule tête multi-sortie ?
  - Le contrat existant (n8n, README) dépend de "prediction" == "True Positive" avec un
    seuil de confiance — on ne veut pas risquer de le casser en changeant la nature de la
    sortie du premier modèle.
  - Les deux tâches ont des distributions de classes très différentes (binaire ~40/60 vs
    8 classes dont certaines très minoritaires) ; les garder séparés simplifie l'évaluation
    et permet de retravailler l'une sans re-valider l'autre.

Les features sont exactement les mêmes que pour le modèle binaire (FEATURE_COLUMNS de
feature_engineering.py, y compris has_sqli_pattern/sqli_keyword_count et les groupes SQL).

ATTENTION sur la qualité des labels "category" : ils sont dérivés heuristiquement (voir
src/attack_category.py), pas annotés par un humain — c'est un point de départ raisonnable
(le modèle apprend à généraliser cette heuristique à des combinaisons de features qu'elle
n'a pas vues explicitement), mais à re-valider avec de vraies alertes labellisées par les
analystes du SOC cible dès que possible (voir README, Roadmap).

Usage :
    python -m src.train_category_model --data data/processed/training_data.csv \
        --output models/rf_category_classifier.joblib
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

from src.attack_category import CATEGORIES
from src.feature_engineering import FEATURE_COLUMNS


def train(data_path: str, output_path: str, test_size: float = 0.2, random_state: int = 42) -> None:
    df = pd.read_csv(data_path)

    if "category" not in df.columns:
        raise ValueError(
            "Le CSV d'entraînement doit contenir une colonne 'category' — régénère-le via "
            "`python -m src.convert_hf_dataset` (met à jour convert_hf_dataset.py si besoin)."
        )

    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Colonnes de features manquantes dans le CSV : {missing}")

    X = df[FEATURE_COLUMNS].fillna(0)
    y = df["category"].astype(str)

    counts = y.value_counts()
    print(f"[train_category_model] Dataset : {len(df)} lignes, répartition catégories :\n{counts}")
    thin = counts[counts < 10]
    if not thin.empty:
        print(
            f"[train_category_model] ATTENTION : catégories avec <10 exemples : {thin.to_dict()} — "
            "les métriques ci-dessous seront peu fiables pour ces classes, à consolider avec de "
            "vraies alertes labellisées dès que possible."
        )

    # stratify uniquement si chaque classe a au moins 2 exemples (sinon train_test_split échoue)
    can_stratify = (counts >= 2).all()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y if can_stratify else None
    )

    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=1,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("\n[train_category_model] Rapport de classification (jeu de test, split unique 80/20) :")
    print(classification_report(y_test, y_pred, zero_division=0))
    print("[train_category_model] Matrice de confusion (ordre = clf.classes_) :")
    print(clf.classes_)
    print(confusion_matrix(y_test, y_pred, labels=clf.classes_))

    # Validation croisée stratifiée sur l'ensemble du dataset, en plus du split 80/20 ci-dessus —
    # avec plusieurs classes minoritaires (<20 exemples), un seul split donne des métriques très
    # bruitées (support de quelques unités par classe dans le jeu de test). n_splits est plafonné
    # au nombre d'exemples de la classe la plus rare (StratifiedKFold l'exige). N'affecte PAS le
    # modèle sauvegardé (toujours celui entraîné sur X_train ci-dessus).
    min_class_count = int(counts.min())
    n_splits = max(2, min(5, min_class_count))
    if min_class_count < 2:
        print(
            f"\n[train_category_model] Validation croisée ignorée : au moins une catégorie n'a "
            f"qu'{min_class_count} exemple, StratifiedKFold nécessite >=2 exemples par classe."
        )
    else:
        cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
        cv_results = cross_validate(
            clone(clf), X, y, cv=cv,
            scoring=["accuracy", "f1_macro", "precision_macro", "recall_macro"],
        )
        print(f"\n[train_category_model] Validation croisée stratifiée ({n_splits}-fold, ensemble du dataset) :")
        for metric in ["accuracy", "f1_macro", "precision_macro", "recall_macro"]:
            scores = cv_results[f"test_{metric}"]
            print(f"  {metric:<18} {scores.mean():.4f} ± {scores.std():.4f}  (folds: {np.round(scores, 4).tolist()})")

    importances = sorted(zip(FEATURE_COLUMNS, clf.feature_importances_), key=lambda x: x[1], reverse=True)
    print("\n[train_category_model] Top features (importance décroissante) :")
    for name, imp in importances[:12]:
        print(f"  {name:<30} {imp:.4f}")

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": clf,
            "feature_columns": FEATURE_COLUMNS,
            "classes": clf.classes_.tolist(),
            "category_meta": CATEGORIES,
        },
        out,
    )
    print(f"\n[train_category_model] Modèle sauvegardé dans {out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Entraîne le classifieur RandomForest multi-classe (catégorie d'attaque).")
    parser.add_argument("--data", default="data/processed/training_data.csv", help="CSV de features labellisées")
    parser.add_argument("--output", default="models/rf_category_classifier.joblib", help="Chemin de sauvegarde du modèle")
    parser.add_argument("--test-size", type=float, default=0.2)
    args = parser.parse_args()

    train(args.data, args.output, test_size=args.test_size)
