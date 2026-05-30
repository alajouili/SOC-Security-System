"""
Analyze Route — POST /analyze — Cœur du système SOC.
Pipeline complet : validation → sanitization → SSRF → ML → scoring → alerte.
Latence cible p99 ≤ 200ms.
"""

import time
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.database import get_db
from app.database.models import Log, User
from app.middleware.rate_limiter import limiter
from app.schemas.log_schema import LogEntry
from app.security.input_sanitizer import sanitize_log_entry
from app.security.permissions import require_authenticated
from app.services.alerts_engine import process_alert
from app.services.anomaly_detection import analyze_entry
from app.services.scoring import compute_risk_score
from app.services.ssrf_guard import validate_log_entry_for_ssrf
from app.monitoring.metrics import (
    ANALYZE_LATENCY,
    ANOMALY_RATE,
    HIGH_RISK_COUNT,
)

log = structlog.get_logger(__name__)
router = APIRouter()


@router.post(
    "/analyze",
    summary="Analyse de sécurité d'un log",
    response_model=dict,
)
@limiter.limit("60/minute")
async def analyze_log(
    request: Request,
    entry: LogEntry,
    current_user: User = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """
    Analyse une entrée de log et retourne le score de risque, le niveau et les techniques.

    Pipeline d'analyse :
    1. Validation Pydantic (déjà effectuée par FastAPI)
    2. Sanitization des entrées (SQLi, XSS, Path Traversal)
    3. Vérification SSRF
    4. Inférence Isolation Forest (timeout 100ms)
    5. Calcul du risk score [0–100]
    6. Persistance en base
    7. Génération d'alerte si score ≥ 31
    8. Réponse

    Latence cible p99 ≤ 200ms.
    """
    t_start = time.monotonic()

    # ── Conversion en dictionnaire pour le pipeline ───────────────────────
    entry_dict = {
        "ip": str(entry.ip),
        "endpoint": entry.endpoint,
        "method": entry.method.value,
        "status_code": entry.status_code,
        "requests_per_minute": entry.requests_per_minute,
        "response_time": entry.response_time,
        "user_agent": entry.user_agent,
        "timestamp": entry.timestamp,
    }

    # ── Étape 1 : Sanitization des entrées string ─────────────────────────
    sanitized_dict, detected_threats = sanitize_log_entry(entry_dict)

    # ── Étape 2 : Vérification SSRF ───────────────────────────────────────
    ssrf_fields = validate_log_entry_for_ssrf(entry_dict)

    # ── Étape 3 : Inférence ML ────────────────────────────────────────────
    try:
        anomaly_result = analyze_entry(entry_dict)
    except RuntimeError as exc:
        log.error("model_unavailable", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service d'analyse temporairement indisponible.",
        ) from exc

    # ── Étape 4 : Calcul du risk score ────────────────────────────────────
    scoring = compute_risk_score(
        entry=entry_dict,
        detected_threats=detected_threats,
        ssrf_fields=ssrf_fields,
        anomaly_result=anomaly_result,
    )

    # ── Étape 5 : Persistance ─────────────────────────────────────────────
    from app.database.models import HttpMethod

    log_record = Log(
        ip=str(entry.ip),
        endpoint=entry.endpoint,
        method=HttpMethod(entry.method.value),
        status_code=entry.status_code,
        response_time=entry.response_time,
        requests_per_minute=entry.requests_per_minute,
        risk_score=scoring.risk_score,
        anomaly=anomaly_result.is_anomaly,
        user_agent=entry.user_agent,
        user_id=current_user.id,
        timestamp=entry.timestamp,
    )
    db.add(log_record)
    await db.flush()
    log_id = log_record.id

    # ── Étape 6 : Génération d'alerte ─────────────────────────────────────
    alert = await process_alert(
        scoring=scoring,
        entry=entry_dict,
        db=db,
        log_id=log_id,
    )
    await db.commit()

    # ── Métriques Prometheus ──────────────────────────────────────────────
    latency_ms = (time.monotonic() - t_start) * 1000
    ANALYZE_LATENCY.observe(latency_ms)

    if anomaly_result.is_anomaly:
        ANOMALY_RATE.inc()

    if scoring.risk_level == "HIGH":
        HIGH_RISK_COUNT.inc()

    log.info(
        "analyze_complete",
        ip=str(entry.ip),
        score=scoring.risk_score,
        level=scoring.risk_level,
        techniques=scoring.techniques,
        latency_ms=round(latency_ms, 2),
        user_id=current_user.id,
    )

    return {
        "log_id": log_id,
        "risk_score": scoring.risk_score,
        "risk_level": scoring.risk_level,
        "is_anomaly": anomaly_result.is_anomaly,
        "techniques": scoring.techniques,
        "owasp_ref": scoring.owasp_ref,
        "score_breakdown": scoring.score_breakdown,
        "feature_importance": anomaly_result.feature_importance,
        "inference_time_ms": anomaly_result.inference_time_ms,
        "total_latency_ms": round(latency_ms, 2),
        "alert_id": alert.id if alert else None,
    }