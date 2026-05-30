"""
Preprocessing — Pipeline de préparation des données pour l'Isolation Forest.
Sanitization, encodage, normalisation, imputation des valeurs manquantes.
"""

import os
import pickle
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import structlog
from sklearn.preprocessing import LabelEncoder, StandardScaler

log = structlog.get_logger(__name__)

# ── Features utilisées par le modèle ────────────────────────────────────────
FEATURE_COLUMNS = [
    "status_code",
    "requests_per_minute",
    "response_time",
    "method_encoded",
    "endpoint_risk",
    "is_sensitive_endpoint",
    "hour_of_day",
]

# Endpoints sensibles (contribuent au scoring de risque)
_SENSITIVE_ENDPOINTS = {
    "/login", "/auth/login", "/admin", "/api/auth",
    "/password/reset", "/api/users", "/api/admin",
    "/register", "/auth/register", "/.env", "/config",
    "/actuator", "/api/keys",
}

# Encodage ordinal des méthodes HTTP (stable entre entraînement et inférence)
_METHOD_ENCODING = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3, "PATCH": 4}


def _encode_method(method: str) -> int:
    """Encode la méthode HTTP en entier (stable, pas de LabelEncoder)."""
    return _METHOD_ENCODING.get(method.upper(), 0)


def _compute_endpoint_risk(endpoint: str) -> float:
    """
    Score de risque basé sur l'endpoint (0.0–1.0).
    Les endpoints sensibles reçoivent un score élevé.
    """
    endpoint_lower = endpoint.lower()

    # Correspondance exacte
    if endpoint_lower in _SENSITIVE_ENDPOINTS:
        return 1.0

    # Correspondance partielle sur segments sensibles
    sensitive_keywords = [
        "admin", "auth", "login", "password", "token",
        "key", "secret", "config", "debug", "actuator",
        "backup", "dump", "export", "internal",
    ]
    for kw in sensitive_keywords:
        if kw in endpoint_lower:
            return 0.7

    return 0.0


def _is_sensitive_endpoint(endpoint: str) -> int:
    """Retourne 1 si l'endpoint est sensible, 0 sinon."""
    return int(_compute_endpoint_risk(endpoint) >= 0.7)


def extract_features(entry: dict[str, Any]) -> dict[str, float]:
    """
    Extrait les features d'une entrée de log brute.
    Cette fonction est identique en entraînement et en inférence.

    Args:
        entry: Dictionnaire avec les champs du LogEntry.

    Returns:
        Dictionnaire de features numériques.
    """
    from datetime import datetime

    timestamp = entry.get("timestamp")
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp)
        except (ValueError, TypeError):
            timestamp = None

    hour_of_day = timestamp.hour if timestamp else 12

    method = str(entry.get("method", "GET"))
    endpoint = str(entry.get("endpoint", "/"))
    status_code = float(entry.get("status_code", 200))
    rpm = float(entry.get("requests_per_minute", 0.0))
    response_time = float(entry.get("response_time", 0.0))

    return {
        "status_code": status_code,
        "requests_per_minute": rpm,
        "response_time": response_time,
        "method_encoded": float(_encode_method(method)),
        "endpoint_risk": _compute_endpoint_risk(endpoint),
        "is_sensitive_endpoint": float(_is_sensitive_endpoint(endpoint)),
        "hour_of_day": float(hour_of_day),
    }


def build_feature_matrix(entries: list[dict[str, Any]]) -> np.ndarray:
    """
    Construit la matrice de features pour un lot d'entrées.

    Args:
        entries: Liste de dictionnaires de logs.

    Returns:
        Matrice numpy (n_samples, n_features).
    """
    rows = [extract_features(e) for e in entries]
    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)

    # Imputation médiane pour valeurs manquantes
    for col in FEATURE_COLUMNS:
        if df[col].isna().any():
            median_val = df[col].median()
            df[col] = df[col].fillna(median_val)
            log.warning("feature_imputation", column=col, median=median_val)

    # Vérification out-of-range
    if (df["requests_per_minute"] > 10000).any():
        log.warning("feature_out_of_range", column="requests_per_minute")
        df["requests_per_minute"] = df["requests_per_minute"].clip(upper=10000)

    if (df["status_code"] < 100).any() or (df["status_code"] > 599).any():
        log.warning("feature_out_of_range", column="status_code")
        df["status_code"] = df["status_code"].clip(lower=100, upper=599)

    return df[FEATURE_COLUMNS].values.astype(np.float64)


def get_feature_names() -> list[str]:
    """Retourne la liste ordonnée des noms de features."""
    return list(FEATURE_COLUMNS)