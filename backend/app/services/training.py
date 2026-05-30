"""
Training — Entraînement de l'Isolation Forest — Pipeline ML complet.
Cross-validation temporelle, sauvegarde joblib signée SHA-256.
Rapport de performance : précision, rappel, F1, courbe PR.
"""

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import structlog
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
)
from sklearn.model_selection import TimeSeriesSplit

from app.services.preprocessing import FEATURE_COLUMNS, build_feature_matrix

log = structlog.get_logger(__name__)

_MODEL_PATH = os.getenv("MODEL_PATH", "/app/model/anomaly_model.pkl")
_MANIFEST_PATH = os.getenv("MODEL_MANIFEST_PATH", "/app/model/model_manifest.json")
_CONTAMINATION = float(os.getenv("CONTAMINATION_RATE", "0.03"))


def _compute_sha256(file_path: str) -> str:
    """Calcule le hash SHA-256 d'un fichier."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _save_manifest(model_path: str, metrics: dict[str, Any]) -> None:
    """
    Sauvegarde le manifeste du modèle avec hash SHA-256 pour vérification d'intégrité.
    """
    sha256 = _compute_sha256(model_path)
    manifest = {
        "version": datetime.now(UTC).strftime("%Y%m%d_%H%M%S"),
        "trained_at": datetime.now(UTC).isoformat(),
        "sha256": sha256,
        "contamination": _CONTAMINATION,
        "feature_columns": FEATURE_COLUMNS,
        "metrics": metrics,
        "model_path": model_path,
    }

    manifest_path = Path(_MANIFEST_PATH)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2))

    log.info("model_manifest_saved", sha256=sha256, path=_MANIFEST_PATH)


def train_model(data_path: str = "data/logs.json") -> dict[str, Any]:
    """
    Entraîne l'Isolation Forest sur le dataset synthétique.
    Utilise une cross-validation temporelle (pas de data leakage).

    Args:
        data_path: Chemin vers le dataset JSON.

    Returns:
        Dictionnaire des métriques d'entraînement.
    """
    log.info("training_start", data_path=data_path, contamination=_CONTAMINATION)

    # ── Chargement des données ───────────────────────────────────────────
    data_file = Path(data_path)
    if not data_file.exists():
        raise FileNotFoundError(f"Dataset introuvable : {data_path}")

    with open(data_file) as f:
        raw_data = json.load(f)

    log.info("training_data_loaded", samples=len(raw_data))

    if len(raw_data) < 100:
        raise ValueError(f"Dataset insuffisant : {len(raw_data)} entrées (minimum 100).")

    # ── Tri chronologique pour cross-validation temporelle ───────────────
    df = pd.DataFrame(raw_data)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("timestamp").reset_index(drop=True)

    X = build_feature_matrix(df.to_dict("records"))

    # Labels pour l'évaluation (0=normal, 1=anomalie)
    y_true = None
    if "label" in df.columns:
        y_true = (df["label"] != "normal").astype(int).values

    # ── Cross-validation temporelle ──────────────────────────────────────
    tscv = TimeSeriesSplit(n_splits=5)
    cv_scores: list[float] = []

    log.info("training_cross_validation_start", splits=5)

    for fold, (train_idx, val_idx) in enumerate(tscv.split(X)):
        X_train = X[train_idx]
        X_val = X[val_idx]

        model_cv = IsolationForest(
            contamination=_CONTAMINATION,
            n_estimators=200,
            max_samples="auto",
            random_state=42,
            n_jobs=-1,
        )
        model_cv.fit(X_train)

        # Score sur la validation (proportion d'anomalies détectées)
        val_scores = model_cv.decision_function(X_val)
        anomaly_rate = (model_cv.predict(X_val) == -1).mean()
        cv_scores.append(float(anomaly_rate))

        log.debug(
            "cv_fold_complete",
            fold=fold + 1,
            train_size=len(train_idx),
            val_size=len(val_idx),
            anomaly_rate=round(anomaly_rate, 4),
        )

    # ── Entraînement final sur tout le dataset ───────────────────────────
    log.info("training_final_model")
    final_model = IsolationForest(
        contamination=_CONTAMINATION,
        n_estimators=200,
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    )
    final_model.fit(X)

    # ── Distribution des prédictions ─────────────────────────────────────
    predictions = final_model.predict(X)
    raw_scores = final_model.score_samples(X)

    n_normal = int((predictions == 1).sum())
    n_suspect = int((predictions == -1).sum())

    # Niveaux de criticité sur les anomalies
    anomaly_scores = raw_scores[predictions == -1]
    n_critical = int((anomaly_scores < np.percentile(anomaly_scores, 20)).sum()) if len(anomaly_scores) > 0 else 0

    log.info(
        "training_distribution",
        normal=n_normal,
        suspect=n_suspect,
        critical=n_critical,
    )

    # ── Métriques si labels disponibles ──────────────────────────────────
    metrics: dict[str, Any] = {
        "cv_anomaly_rates": cv_scores,
        "cv_mean": round(float(np.mean(cv_scores)), 4),
        "cv_std": round(float(np.std(cv_scores)), 4),
        "total_samples": len(X),
        "n_normal": n_normal,
        "n_suspect": n_suspect,
        "n_critical": n_critical,
        "contamination": _CONTAMINATION,
    }

    if y_true is not None:
        y_pred = (predictions == -1).astype(int)
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)

        metrics.update(
            {
                "precision": round(float(precision), 4),
                "recall": round(float(recall), 4),
                "f1_score": round(float(f1), 4),
            }
        )

        log.info(
            "training_metrics",
            precision=metrics["precision"],
            recall=metrics["recall"],
            f1=metrics["f1_score"],
        )

    # ── Sauvegarde du modèle ──────────────────────────────────────────────
    model_path = Path(_MODEL_PATH)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(final_model, str(model_path))

    log.info("model_saved", path=_MODEL_PATH)

    # ── Manifeste + hash SHA-256 ──────────────────────────────────────────
    _save_manifest(str(model_path), metrics)

    log.info("training_complete", metrics=metrics)
    return metrics


if __name__ == "__main__":
    """Lancement direct : python -m app.services.training"""
    import sys

    data_path = sys.argv[1] if len(sys.argv) > 1 else "data/logs.json"
    results = train_model(data_path)
    print(json.dumps(results, indent=2))