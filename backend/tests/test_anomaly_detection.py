"""
Tests unitaires — anomaly_detection.py
Tests sur preprocessing, normalisation, feature extraction et inférence mockée.
"""

import hashlib
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from app.services.anomaly_detection import (
    AnomalyResult,
    _compute_feature_importance,
    _normalize_score,
    _verify_model_integrity,
)
from app.services.preprocessing import (
    FEATURE_COLUMNS,
    _compute_endpoint_risk,
    _encode_method,
    _is_sensitive_endpoint,
    build_feature_matrix,
    extract_features,
)


# ── Tests preprocessing ───────────────────────────────────────────────────────

class TestPreprocessing:
    def _sample_entry(self, **kwargs) -> dict:
        base = {
            "ip": "192.168.1.1",
            "endpoint": "/home",
            "method": "GET",
            "status_code": 200,
            "requests_per_minute": 10.0,
            "response_time": 150.0,
            "user_agent": "Mozilla/5.0",
            "timestamp": "2026-01-01T10:00:00+00:00",
        }
        base.update(kwargs)
        return base

    def test_extract_features_returns_correct_keys(self):
        features = extract_features(self._sample_entry())
        assert set(features.keys()) == set(FEATURE_COLUMNS)

    def test_all_feature_values_are_numeric(self):
        features = extract_features(self._sample_entry())
        for k, v in features.items():
            assert isinstance(v, (int, float)), f"Feature {k} n'est pas numérique: {v}"

    def test_method_encoding_is_stable(self):
        assert _encode_method("GET") == 0
        assert _encode_method("POST") == 1
        assert _encode_method("PUT") == 2
        assert _encode_method("DELETE") == 3
        assert _encode_method("PATCH") == 4

    def test_unknown_method_returns_zero(self):
        assert _encode_method("OPTIONS") == 0

    def test_sensitive_endpoint_detection(self):
        assert _is_sensitive_endpoint("/login") == 1
        assert _is_sensitive_endpoint("/admin") == 1
        assert _is_sensitive_endpoint("/api/auth") == 1
        assert _is_sensitive_endpoint("/home") == 0
        assert _is_sensitive_endpoint("/products") == 0

    def test_endpoint_risk_score_range(self):
        for ep in ["/login", "/admin", "/home", "/api/users/profile"]:
            score = _compute_endpoint_risk(ep)
            assert 0.0 <= score <= 1.0, f"Score hors limites pour {ep}: {score}"

    def test_hour_of_day_extracted_correctly(self):
        from datetime import datetime, timezone
        entry = self._sample_entry()
        entry["timestamp"] = datetime(2026, 1, 1, 14, 30, tzinfo=timezone.utc)
        features = extract_features(entry)
        assert features["hour_of_day"] == 14.0

    def test_build_feature_matrix_shape(self):
        entries = [self._sample_entry() for _ in range(10)]
        matrix = build_feature_matrix(entries)
        assert matrix.shape == (10, len(FEATURE_COLUMNS))

    def test_feature_matrix_dtype_is_float64(self):
        entries = [self._sample_entry()]
        matrix = build_feature_matrix(entries)
        assert matrix.dtype == np.float64

    def test_rpm_clamped_at_10000(self):
        entry = self._sample_entry(requests_per_minute=99999.0)
        matrix = build_feature_matrix([entry])
        rpm_idx = FEATURE_COLUMNS.index("requests_per_minute")
        assert matrix[0, rpm_idx] <= 10000.0

    def test_status_code_clamped(self):
        entry = self._sample_entry(status_code=9999)
        matrix = build_feature_matrix([entry])
        sc_idx = FEATURE_COLUMNS.index("status_code")
        assert matrix[0, sc_idx] <= 599.0

    def test_string_timestamp_parsed(self):
        entry = self._sample_entry(timestamp="2026-06-15T08:00:00+00:00")
        features = extract_features(entry)
        assert features["hour_of_day"] == 8.0

    def test_none_timestamp_defaults_to_noon(self):
        entry = self._sample_entry(timestamp=None)
        features = extract_features(entry)
        assert features["hour_of_day"] == 12.0


# ── Tests normalisation du score ──────────────────────────────────────────────

class TestNormalizeScore:
    def test_zero_score_maps_to_half(self):
        # score_samples ~ 0 pour les normaux → normalisé ~ 0.5
        result = _normalize_score(0.0)
        assert abs(result - 0.5) < 0.01

    def test_negative_score_maps_above_half(self):
        # Scores négatifs → anomalies → valeur normalisée > 0.5
        result = _normalize_score(-0.3)
        assert result > 0.5

    def test_score_clamped_at_0(self):
        result = _normalize_score(10.0)  # très positif → très normal
        assert result == 0.0

    def test_score_clamped_at_1(self):
        result = _normalize_score(-10.0)  # très négatif → anomalie certaine
        assert result == 1.0

    def test_output_always_in_range(self):
        for raw in [-1.0, -0.5, -0.1, 0.0, 0.1, 0.5, 1.0]:
            result = _normalize_score(raw)
            assert 0.0 <= result <= 1.0, f"Valeur hors limites pour input {raw}: {result}"


# ── Tests feature importance ──────────────────────────────────────────────────

class TestFeatureImportance:
    def test_returns_all_feature_names(self):
        mock_model = MagicMock()
        features = np.array([200.0, 50.0, 100.0, 1.0, 0.0, 0.0, 10.0])
        importance = _compute_feature_importance(mock_model, features)
        assert set(importance.keys()) == set(FEATURE_COLUMNS)

    def test_importance_values_are_floats(self):
        mock_model = MagicMock()
        features = np.array([200.0, 50.0, 100.0, 1.0, 0.5, 1.0, 14.0])
        importance = _compute_feature_importance(mock_model, features)
        for k, v in importance.items():
            assert isinstance(v, float), f"{k}: {v} n'est pas un float"

    def test_importance_values_sum_to_one(self):
        mock_model = MagicMock()
        features = np.array([200.0, 50.0, 100.0, 1.0, 0.7, 1.0, 14.0])
        importance = _compute_feature_importance(mock_model, features)
        total = sum(importance.values())
        assert abs(total - 1.0) < 0.01


# ── Tests intégrité du modèle ─────────────────────────────────────────────────

class TestModelIntegrity:
    def test_missing_manifest_returns_false(self, tmp_path):
        with patch("app.services.anomaly_detection._MANIFEST_PATH", str(tmp_path / "missing.json")):
            with patch("app.services.anomaly_detection._MODEL_PATH", str(tmp_path / "model.pkl")):
                assert _verify_model_integrity() is False

    def test_missing_model_file_returns_false(self, tmp_path):
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps({"sha256": "abc123"}))
        with patch("app.services.anomaly_detection._MANIFEST_PATH", str(manifest)):
            with patch("app.services.anomaly_detection._MODEL_PATH", str(tmp_path / "missing.pkl")):
                assert _verify_model_integrity() is False

    def test_hash_mismatch_returns_false(self, tmp_path):
        model_file = tmp_path / "model.pkl"
        model_file.write_bytes(b"fake model content")

        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps({"sha256": "wronghash123"}))

        with patch("app.services.anomaly_detection._MANIFEST_PATH", str(manifest)):
            with patch("app.services.anomaly_detection._MODEL_PATH", str(model_file)):
                assert _verify_model_integrity() is False

    def test_correct_hash_returns_true(self, tmp_path):
        model_file = tmp_path / "model.pkl"
        content = b"fake model content for testing"
        model_file.write_bytes(content)

        sha256 = hashlib.sha256(content).hexdigest()
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps({"sha256": sha256}))

        with patch("app.services.anomaly_detection._MANIFEST_PATH", str(manifest)):
            with patch("app.services.anomaly_detection._MODEL_PATH", str(model_file)):
                assert _verify_model_integrity() is True

    def test_manifest_without_sha256_returns_false(self, tmp_path):
        model_file = tmp_path / "model.pkl"
        model_file.write_bytes(b"content")

        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps({"version": "1.0"}))  # Pas de sha256

        with patch("app.services.anomaly_detection._MANIFEST_PATH", str(manifest)):
            with patch("app.services.anomaly_detection._MODEL_PATH", str(model_file)):
                assert _verify_model_integrity() is False


# ── Tests AnomalyResult dataclass ─────────────────────────────────────────────

class TestAnomalyResult:
    def test_is_anomaly_flag(self):
        r = AnomalyResult(
            anomaly_score=-0.2,
            normalized_score=0.7,
            prediction=-1,
            is_anomaly=True,
            risk_level="HIGH",
            feature_importance={},
            inference_time_ms=10.0,
        )
        assert r.is_anomaly is True
        assert r.risk_level == "HIGH"

    def test_normal_prediction(self):
        r = AnomalyResult(
            anomaly_score=0.05,
            normalized_score=0.1,
            prediction=1,
            is_anomaly=False,
            risk_level="LOW",
            feature_importance={},
            inference_time_ms=5.0,
        )
        assert r.is_anomaly is False
        assert r.prediction == 1