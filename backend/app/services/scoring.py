"""
Scoring — Risk Score 0–100 avec signaux pondérés.
Calibration multi-signal : RPM, codes HTTP, endpoints, ML, SQLi, XSS, brute force, SSRF.
Les poids sont des hypothèses initiales à calibrer sur données réelles (30j de prod).
"""

from dataclasses import dataclass, field
from typing import Any

import structlog

from app.services.anomaly_detection import AnomalyResult

log = structlog.get_logger(__name__)

# ── Constantes de seuil ───────────────────────────────────────────────────────
_RPM_SUSPECT = 60.0
_RPM_CRITICAL = 100.0
_BRUTE_FORCE_THRESHOLD = 5  # Erreurs 401 consécutives pour déclencher +5


@dataclass
class RiskSignals:
    """Signaux de risque détectés pour une entrée de log."""

    # Depuis le log brut
    has_high_rpm: bool = False
    has_critical_rpm: bool = False
    has_auth_errors: bool = False          # 401/403 répétés
    is_sensitive_endpoint: bool = False
    has_sqli: bool = False
    has_xss: bool = False
    has_path_traversal: bool = False
    has_ssrf: bool = False
    has_brute_force: bool = False

    # Depuis le modèle ML
    anomaly_normalized_score: float = 0.0

    # Contexte
    detected_techniques: list[str] = field(default_factory=list)
    owasp_references: list[str] = field(default_factory=list)


@dataclass
class ScoringResult:
    """Résultat complet du scoring de risque."""

    risk_score: float              # Score final [0, 100]
    risk_level: str                # LOW / MEDIUM / HIGH
    signals: RiskSignals
    score_breakdown: dict[str, float]
    techniques: list[str]
    owasp_ref: str | None


_SENSITIVE_ENDPOINTS = {
    "/login", "/auth/login", "/admin", "/api/auth", "/password",
    "/password/reset", "/api/users", "/api/admin", "/register",
    "/auth/register", "/.env", "/config", "/actuator", "/api/keys",
    "/api/tokens", "/oauth", "/saml",
}


def _detect_signals(
    entry: dict[str, Any],
    detected_threats: list[str],
    ssrf_fields: list[str],
    anomaly_result: AnomalyResult,
) -> RiskSignals:
    """
    Détecte tous les signaux de risque présents dans une entrée.

    Args:
        entry: Données du log.
        detected_threats: Menaces détectées par input_sanitizer.
        ssrf_fields: Champs SSRF détectés par ssrf_guard.
        anomaly_result: Résultat de l'analyse Isolation Forest.

    Returns:
        RiskSignals avec tous les signaux positifs.
    """
    signals = RiskSignals()

    # ── RPM ────────────────────────────────────────────────────────────────
    rpm = float(entry.get("requests_per_minute", 0.0))
    signals.has_high_rpm = rpm > _RPM_SUSPECT
    signals.has_critical_rpm = rpm > _RPM_CRITICAL

    # ── Codes HTTP (erreurs d'authentification) ────────────────────────────
    status_code = int(entry.get("status_code", 200))
    signals.has_auth_errors = status_code in (401, 403)

    # ── Endpoint sensible ──────────────────────────────────────────────────
    endpoint = str(entry.get("endpoint", "/")).lower()
    signals.is_sensitive_endpoint = any(
        ep in endpoint for ep in _SENSITIVE_ENDPOINTS
    )

    # ── Menaces injectées ──────────────────────────────────────────────────
    signals.has_sqli = "sql_injection" in detected_threats
    signals.has_xss = "xss" in detected_threats
    signals.has_path_traversal = "path_traversal" in detected_threats
    signals.has_ssrf = bool(ssrf_fields)

    # ── Score ML ───────────────────────────────────────────────────────────
    signals.anomaly_normalized_score = anomaly_result.normalized_score

    # ── Techniques détectées ──────────────────────────────────────────────
    techniques = []
    if signals.has_sqli:
        techniques.append("sql_injection")
        signals.owasp_references.append("A03:2021")
    if signals.has_xss:
        techniques.append("xss")
        signals.owasp_references.append("A03:2021")
    if signals.has_path_traversal:
        techniques.append("path_traversal")
        signals.owasp_references.append("A01:2021")
    if signals.has_ssrf:
        techniques.append("ssrf")
        signals.owasp_references.append("A10:2021")
    if signals.has_critical_rpm or signals.has_high_rpm:
        techniques.append("rate_abuse")
        signals.owasp_references.append("A07:2021")
    if signals.has_auth_errors and signals.is_sensitive_endpoint:
        techniques.append("brute_force")
        signals.owasp_references.append("A07:2021")
    if anomaly_result.is_anomaly:
        techniques.append("anomaly_detected")

    signals.detected_techniques = list(set(techniques))
    return signals


def compute_risk_score(
    entry: dict[str, Any],
    detected_threats: list[str],
    ssrf_fields: list[str],
    anomaly_result: AnomalyResult,
) -> ScoringResult:
    """
    Calcule le score de risque final [0–100] par combinaison de signaux pondérés.

    ⚠️  Les poids ci-dessous sont des hypothèses initiales.
    À calibrer sur données réelles après 30 jours de production.

    Args:
        entry: Données du LogEntry.
        detected_threats: Sorties de input_sanitizer.
        ssrf_fields: Sorties de ssrf_guard.
        anomaly_result: Résultat de anomaly_detection.

    Returns:
        ScoringResult complet.
    """
    signals = _detect_signals(entry, detected_threats, ssrf_fields, anomaly_result)
    breakdown: dict[str, float] = {}
    score = 0.0

    # ── Signal 1 : RPM (+20 max) ──────────────────────────────────────────
    rpm = float(entry.get("requests_per_minute", 0.0))
    if signals.has_critical_rpm:
        rpm_score = 20.0
    elif signals.has_high_rpm:
        rpm_score = 10.0
    else:
        rpm_score = 0.0
    breakdown["requests_per_minute"] = rpm_score
    score += rpm_score

    # ── Signal 2 : Erreurs HTTP 4xx/5xx (+20 max) ─────────────────────────
    status_code = int(entry.get("status_code", 200))
    if status_code in (401, 403):
        http_score = 20.0
    elif 400 <= status_code < 600:
        http_score = 8.0
    else:
        http_score = 0.0
    breakdown["http_error"] = http_score
    score += http_score

    # ── Signal 3 : Endpoint sensible (+15) ────────────────────────────────
    endpoint_score = 15.0 if signals.is_sensitive_endpoint else 0.0
    breakdown["sensitive_endpoint"] = endpoint_score
    score += endpoint_score

    # ── Signal 4 : Score Isolation Forest (+20 max) ───────────────────────
    ml_score = signals.anomaly_normalized_score * 20.0
    breakdown["isolation_forest"] = round(ml_score, 2)
    score += ml_score

    # ── Signal 5 : SQL Injection (+10) ────────────────────────────────────
    sqli_score = 10.0 if signals.has_sqli else 0.0
    breakdown["sql_injection"] = sqli_score
    score += sqli_score

    # ── Signal 6 : XSS (+10) ──────────────────────────────────────────────
    xss_score = 10.0 if signals.has_xss else 0.0
    breakdown["xss"] = xss_score
    score += xss_score

    # ── Signal 7 : Brute force (+5) ───────────────────────────────────────
    bf_score = 5.0 if (signals.has_auth_errors and signals.is_sensitive_endpoint) else 0.0
    breakdown["brute_force"] = bf_score
    score += bf_score

    # ── Signal 8 : Path traversal / SSRF (+10) ────────────────────────────
    traversal_score = 10.0 if (signals.has_path_traversal or signals.has_ssrf) else 0.0
    breakdown["path_traversal_ssrf"] = traversal_score
    score += traversal_score

    # ── Clamp 0–100 ───────────────────────────────────────────────────────
    final_score = min(max(round(score, 2), 0.0), 100.0)

    # ── Niveau de risque ──────────────────────────────────────────────────
    if final_score >= 71:
        risk_level = "HIGH"
    elif final_score >= 31:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # ── OWASP ref principale ──────────────────────────────────────────────
    owasp_ref = signals.owasp_references[0] if signals.owasp_references else None

    log.debug(
        "risk_score_computed",
        score=final_score,
        level=risk_level,
        techniques=signals.detected_techniques,
    )

    return ScoringResult(
        risk_score=final_score,
        risk_level=risk_level,
        signals=signals,
        score_breakdown=breakdown,
        techniques=signals.detected_techniques,
        owasp_ref=owasp_ref,
    )