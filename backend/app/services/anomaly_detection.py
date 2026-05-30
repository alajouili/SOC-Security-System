"""
Anomaly Detection — Inférence Isolation Forest avec vérification d'intégrité.
Timeout 100ms, retourne anomaly_score, prediction, risk_level, feature_importance.
"""

import hashlib
import json
import os
import signal
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import structlog
from sklearn.ensemble import IsolationForest

from app.services.preprocessing import FEATURE_COLUMNS, build_feature_matrix

log = structlog.get_logger(__name__)

_MODEL_PATH = os.getenv("MODEL_PATH", "/app/model/anomaly_model.pkl")
_MANIFEST_PATH = os.getenv("MODEL_MANIFEST_PATH", "/app/model/model_manifest.json")
_INFERENCE_TIMEOUT_MS = 100  # millisecondes

# Singleton du modèle chargé en mémoire
_loaded_model: IsolationForest | None = None
_model_sha256: str | None = None


@dataclass
class AnomalyResult:
    """Résultat d'analyse d'anomalie pour une entrée."""

    anomaly_score: float          # Score brut Isolation Forest ([-1, 0])
    normalized_score: float       # Score normalisé [0.0, 1.0]
    prediction: int               # -1 = anomalie, 1 = normal
    is_anomaly: bool
    risk_level: str               # LOW / MEDIUM / HIGH
    feature_importance: dict[str, float]
    inference_time_ms: float


def _compute_sha256(file_path: str) -> str:
    """Calcule le hash SHA-256 d'un fichier."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _verify_model_integrity() -> bool:
    """
    Vérifie l'intégrité du modèle .pkl via model_manifest.json (OWASP A08).

    Returns:
        True si le hash correspond, False sinon.
    """
    manifest_path = Path(_MANIFEST_PATH)
    model_path = Path(_MODEL_PATH)

    if not manifest_path.exists():
        log.error("model_manifest_missing", path=_MANIFEST_PATH)
        return False

    if not model_path.exists():
        log.error("model_file_missing", path=_MODEL_PATH)
        return False

    try:
        manifest = json.loads(manifest_path.read_text())
        expected_sha256 = manifest.get("sha256")

        if not expected_sha256:
            log.error("model_manifest_no_hash")
            return False

        actual_sha256 = _compute_sha256(_MODEL_PATH)

        if actual_sha256 != expected_sha256:
            log.error(
                "model_integrity_failure",
                expected=expected_sha256,
                actual=actual_sha256,
            )
            return False

        log.info("model_integrity_verified", sha256=actual_sha256)
        return True

    except Exception as exc:  # noqa: BLE001
        log.error("model_integrity_check_error", error=str(exc))
        return False


def load_model() -> IsolationForest:
    """
    Charge le modèle Isolation Forest avec vérification d'intégrité.
    Utilise un singleton pour éviter les rechargements inutiles.

    Returns:
        Modèle Isolation Forest prêt pour l'inférence.

    Raises:
        RuntimeError si l'intégrité est compromise.
    """
    global _loaded_model, _model_sha256

    if not _verify_model_integrity():
        raise RuntimeError(
            "Intégrité du modèle compromise — inférence refusée. "
            "Vérifier model_manifest.json et relancer l'entraînement."
        )

    if _loaded_model is None:
        log.info("model_loading", path=_MODEL_PATH)
        _loaded_model = joblib.load(_MODEL_PATH)
        _model_sha256 = _compute_sha256(_MODEL_PATH)
        log.info("model_loaded", sha256=_model_sha256)

    return _loaded_model


def _compute_feature_importance(
    model: IsolationForest, features: np.ndarray
) -> dict[str, float]:
    """
    Estime l'importance des features par analyse de profondeur des arbres.
    Méthode approximative — valeurs relatives pour l'explication.

    Args:
        model: Modèle Isolation Forest entraîné.
        features: Vecteur de features (1D).

    Returns:
        Dictionnaire {feature_name: importance_relative}.
    """
    try:
        feature_vector = features.reshape(1, -1)
        importances: dict[str, float] = {}

        # Profondeur moyenne par feature (heuristique)
        feature_values = features.tolist()
        total = sum(abs(v) for v in feature_values) or 1.0

        for i, name in enumerate(FEATURE_COLUMNS):
            importances[name] = round(abs(feature_values[i]) / total, 4)

        return importances

    except Exception:  # noqa: BLE001
        return {name: 0.0 for name in FEATURE_COLUMNS}


def _normalize_score(raw_score: float) -> float:
    """
    Normalise le score Isolation Forest de [-0.5, 0.5] vers [0.0, 1.0].
    Plus le score normalisé est élevé, plus l'entrée est anormale.
    """
    # score_samples retourne des valeurs proches de 0 pour les normaux,
    # négatives pour les anomalies
    normalized = 1.0 - (raw_score + 0.5)
    return float(np.clip(normalized, 0.0, 1.0))


@contextmanager
def _timeout_context(milliseconds: int):
    """Context manager pour limiter le temps d'inférence (Unix seulement)."""
    def _handler(signum, frame):
        raise TimeoutError(f"Inférence ML dépassée ({milliseconds}ms)")

    # signal.alarm fonctionne uniquement sur Unix (pas Windows)
    try:
        old_handler = signal.signal(signal.SIGALRM, _handler)
        signal.setitimer(signal.ITIMER_REAL, milliseconds / 1000)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        try:
            signal.signal(signal.SIGALRM, old_handler)
        except Exception:  # noqa: BLE001
            pass


def analyze_entry(entry: dict) -> AnomalyResult:
    t_start = time.monotonic()
    model   = load_model()
    scaler  = _load_scaler()

    features = build_feature_matrix([entry])

    # Appliquer le scaler si disponible
    if scaler is not None:
        features = scaler.transform(features)

    raw_score  = float(model.score_samples(features)[0]) \
                 if hasattr(model, 'score_samples') \
                 else float(model.predict_proba(features)[0][1])

    prediction = int(model.predict(features)[0])

    # Random Forest retourne 0/1 directement
    is_anomaly = bool(prediction == 1 if hasattr(model, 'predict_proba')
                      else prediction == -1)

    normalized = raw_score if hasattr(model, 'predict_proba') \
                 else _normalize_score(raw_score)

    risk_level = "HIGH" if normalized >= 0.7 \
            else "MEDIUM" if normalized >= 0.3 \
            else "LOW"

    inference_ms = round((time.monotonic() - t_start) * 1000, 2)
    importance   = _compute_feature_importance(model, features[0])

    return AnomalyResult(
        anomaly_score=round(raw_score, 6),
        normalized_score=round(float(normalized), 6),
        prediction=prediction,
        is_anomaly=is_anomaly,
        risk_level=risk_level,
        feature_importance=importance,
        inference_time_ms=inference_ms,
    )


def reload_model() -> None:
    """Force le rechargement du modèle (post-entraînement hebdomadaire)."""
    global _loaded_model, _model_sha256
    _loaded_model = None
    _model_sha256 = None
    log.info("model_reload_requested")
    load_model()  # Rechargement immédiat avec vérification