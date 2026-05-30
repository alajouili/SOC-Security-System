"""
Tests unitaires — scoring.py
Couvre tous les signaux de risque, niveaux et cas limites.
"""

import pytest
from unittest.mock import MagicMock
from app.services.anomaly_detection import AnomalyResult
from app.services.scoring import compute_risk_score, ScoringResult


def _make_anomaly(normalized: float = 0.0, is_anomaly: bool = False) -> AnomalyResult:
    return AnomalyResult(
        anomaly_score=-0.1,
        normalized_score=normalized,
        prediction=-1 if is_anomaly else 1,
        is_anomaly=is_anomaly,
        risk_level="LOW",
        feature_importance={},
        inference_time_ms=5.0,
    )


def _base_entry(**kwargs) -> dict:
    entry = {
        "ip": "10.0.0.1",
        "endpoint": "/home",
        "method": "GET",
        "status_code": 200,
        "requests_per_minute": 10.0,
        "response_time": 100.0,
        "user_agent": "Mozilla/5.0",
        "timestamp": "2026-01-01T10:00:00+00:00",
    }
    entry.update(kwargs)
    return entry


# ── Tests niveau LOW ──────────────────────────────────────────────────────────

class TestLowRiskScoring:
    def test_normal_traffic_is_low(self):
        result = compute_risk_score(
            entry=_base_entry(),
            detected_threats=[],
            ssrf_fields=[],
            anomaly_result=_make_anomaly(),
        )
        assert result.risk_level == "LOW"
        assert result.risk_score < 31

    def test_score_is_zero_for_clean_entry(self):
        result = compute_risk_score(
            entry=_base_entry(status_code=200, requests_per_minute=5.0),
            detected_threats=[],
            ssrf_fields=[],
            anomaly_result=_make_anomaly(normalized=0.0),
        )
        assert result.risk_score == 0.0

    def test_score_clamped_at_zero(self):
        result = compute_risk_score(
            entry=_base_entry(),
            detected_threats=[],
            ssrf_fields=[],
            anomaly_result=_make_anomaly(normalized=0.0),
        )
        assert result.risk_score >= 0.0


# ── Tests niveau MEDIUM ───────────────────────────────────────────────────────

class TestMediumRiskScoring:
    def test_high_rpm_gives_medium(self):
        # RPM=70 (+10) + ML=0.5 (+10) + sensitive endpoint (+15) = 35 → MEDIUM
        result = compute_risk_score(
            entry=_base_entry(requests_per_minute=70.0, endpoint="/login"),
            detected_threats=[],
            ssrf_fields=[],
            anomaly_result=_make_anomaly(normalized=0.5, is_anomaly=True),
        )
        assert result.risk_score >= 31
        assert result.risk_level == "MEDIUM"

    def test_auth_error_on_sensitive_endpoint(self):
        result = compute_risk_score(
            entry=_base_entry(status_code=401, endpoint="/login"),
            detected_threats=[],
            ssrf_fields=[],
            anomaly_result=_make_anomaly(normalized=0.2),
        )
        # 20 (401) + 15 (sensitive) + 4 (ML) + 5 (brute) = 44 → MEDIUM
        assert result.risk_score >= 31
        assert result.risk_level in ("MEDIUM", "HIGH")

    def test_techniques_populated_for_rate_abuse(self):
        result = compute_risk_score(
            entry=_base_entry(requests_per_minute=150.0),
            detected_threats=[],
            ssrf_fields=[],
            anomaly_result=_make_anomaly(normalized=0.3),
        )
        assert "rate_abuse" in result.techniques


# ── Tests niveau HIGH ─────────────────────────────────────────────────────────

class TestHighRiskScoring:
    def test_sqli_raises_to_high(self):
        # 401(/login) = 20 + 15 + 5(brute) + 16(ML) + 10(sqli) + 20(RPM) = 86 → HIGH
        result = compute_risk_score(
            entry=_base_entry(
                status_code=401,
                endpoint="/login",
                requests_per_minute=200.0,
            ),
            detected_threats=["sql_injection"],
            ssrf_fields=[],
            anomaly_result=_make_anomaly(normalized=0.8, is_anomaly=True),
        )
        assert result.risk_level == "HIGH"
        assert result.risk_score >= 71
        assert "sql_injection" in result.techniques

    def test_xss_detection(self):
        result = compute_risk_score(
            entry=_base_entry(status_code=401, endpoint="/api/auth"),
            detected_threats=["xss"],
            ssrf_fields=[],
            anomaly_result=_make_anomaly(normalized=0.5, is_anomaly=True),
        )
        assert "xss" in result.techniques
        assert result.risk_score >= 31

    def test_ssrf_detected(self):
        result = compute_risk_score(
            entry=_base_entry(endpoint="/api/fetch"),
            detected_threats=[],
            ssrf_fields=["endpoint"],
            anomaly_result=_make_anomaly(normalized=0.4),
        )
        assert "ssrf" in result.techniques

    def test_path_traversal_detection(self):
        result = compute_risk_score(
            entry=_base_entry(endpoint="/../../../etc/passwd"),
            detected_threats=["path_traversal"],
            ssrf_fields=[],
            anomaly_result=_make_anomaly(normalized=0.3),
        )
        assert "path_traversal" in result.techniques

    def test_all_signals_combined_score_capped_at_100(self):
        result = compute_risk_score(
            entry=_base_entry(
                requests_per_minute=5000.0,
                status_code=401,
                endpoint="/admin",
            ),
            detected_threats=["sql_injection", "xss", "path_traversal"],
            ssrf_fields=["endpoint"],
            anomaly_result=_make_anomaly(normalized=1.0, is_anomaly=True),
        )
        assert result.risk_score <= 100.0
        assert result.risk_level == "HIGH"

    def test_full_score_breakdown_present(self):
        result = compute_risk_score(
            entry=_base_entry(requests_per_minute=200.0, status_code=401, endpoint="/admin"),
            detected_threats=["sql_injection"],
            ssrf_fields=[],
            anomaly_result=_make_anomaly(normalized=0.9, is_anomaly=True),
        )
        expected_keys = {
            "requests_per_minute", "http_error", "sensitive_endpoint",
            "isolation_forest", "sql_injection", "xss", "brute_force", "path_traversal_ssrf"
        }
        assert expected_keys == set(result.score_breakdown.keys())


# ── Tests OWASP references ─────────────────────────────────────────────────────

class TestOwaspReferences:
    def test_sqli_maps_to_a03(self):
        result = compute_risk_score(
            entry=_base_entry(),
            detected_threats=["sql_injection"],
            ssrf_fields=[],
            anomaly_result=_make_anomaly(),
        )
        assert result.owasp_ref == "A03:2021"

    def test_ssrf_maps_to_a10(self):
        result = compute_risk_score(
            entry=_base_entry(),
            detected_threats=[],
            ssrf_fields=["endpoint"],
            anomaly_result=_make_anomaly(),
        )
        assert result.owasp_ref == "A10:2021"

    def test_no_threats_no_owasp_ref(self):
        result = compute_risk_score(
            entry=_base_entry(),
            detected_threats=[],
            ssrf_fields=[],
            anomaly_result=_make_anomaly(normalized=0.0),
        )
        assert result.owasp_ref is None


# ── Tests ML score weight ─────────────────────────────────────────────────────

class TestMLScoreWeight:
    def test_ml_score_contributes_up_to_20(self):
        result_low = compute_risk_score(
            entry=_base_entry(),
            detected_threats=[],
            ssrf_fields=[],
            anomaly_result=_make_anomaly(normalized=0.0),
        )
        result_high = compute_risk_score(
            entry=_base_entry(),
            detected_threats=[],
            ssrf_fields=[],
            anomaly_result=_make_anomaly(normalized=1.0, is_anomaly=True),
        )
        ml_delta = result_high.score_breakdown["isolation_forest"] - result_low.score_breakdown["isolation_forest"]
        assert abs(ml_delta - 20.0) < 0.01

    def test_critical_rpm_gives_20_points(self):
        result = compute_risk_score(
            entry=_base_entry(requests_per_minute=200.0),
            detected_threats=[],
            ssrf_fields=[],
            anomaly_result=_make_anomaly(),
        )
        assert result.score_breakdown["requests_per_minute"] == 20.0

    def test_moderate_rpm_gives_10_points(self):
        result = compute_risk_score(
            entry=_base_entry(requests_per_minute=70.0),
            detected_threats=[],
            ssrf_fields=[],
            anomaly_result=_make_anomaly(),
        )
        assert result.score_breakdown["requests_per_minute"] == 10.0