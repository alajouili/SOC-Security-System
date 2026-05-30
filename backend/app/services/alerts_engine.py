"""
Alerts Engine — Génération et dispatch des alertes.
Alerte créée pour tout score ≥ 31 (MEDIUM).
Dispatch vers WebSocket par rooms de rôle.
"""

import json
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Alert, AlertLevel
from app.services.scoring import ScoringResult

log = structlog.get_logger(__name__)

# Référence globale vers le gestionnaire WebSocket (injecté au démarrage)
_ws_manager: Any | None = None


def set_ws_manager(manager: Any) -> None:
    """Injecte le ConnectionManager WebSocket (évite les imports circulaires)."""
    global _ws_manager
    _ws_manager = manager


def _map_level(risk_level: str) -> AlertLevel:
    """Convertit le niveau de risque en enum AlertLevel."""
    mapping = {
        "HIGH": AlertLevel.HIGH,
        "MEDIUM": AlertLevel.MEDIUM,
        "LOW": AlertLevel.LOW,
    }
    return mapping.get(risk_level, AlertLevel.LOW)


def _build_alert_message(
    scoring: ScoringResult,
    entry: dict[str, Any],
) -> str:
    """Construit le message humain de l'alerte."""
    techniques = scoring.techniques
    endpoint = entry.get("endpoint", "inconnu")
    ip = str(entry.get("ip", "inconnu"))

    if "sql_injection" in techniques:
        return f"SQL Injection détectée sur {endpoint} depuis {ip}"
    if "xss" in techniques:
        return f"XSS détecté sur {endpoint} depuis {ip}"
    if "brute_force" in techniques:
        return f"Tentative de brute force sur {endpoint} depuis {ip}"
    if "ssrf" in techniques:
        return f"Pattern SSRF détecté depuis {ip} vers {endpoint}"
    if "path_traversal" in techniques:
        return f"Path traversal détecté sur {endpoint} depuis {ip}"
    if "rate_abuse" in techniques:
        return f"Abus de débit depuis {ip} ({entry.get('requests_per_minute', '?')} req/min)"
    if "anomaly_detected" in techniques:
        return f"Comportement anormal détecté depuis {ip} sur {endpoint}"

    return f"Activité suspecte détectée (score: {scoring.risk_score}) depuis {ip}"


async def process_alert(
    scoring: ScoringResult,
    entry: dict[str, Any],
    db: AsyncSession,
    log_id: int | None = None,
) -> Alert | None:
    """
    Crée et persiste une alerte si le score est ≥ 31 (MEDIUM).
    Dispatche vers WebSocket en temps réel.

    Args:
        scoring: Résultat complet du scoring.
        entry: Données du log original.
        db: Session de base de données async.
        log_id: ID du log associé (optionnel).

    Returns:
        Instance Alert créée ou None si score trop bas.
    """
    if scoring.risk_score < 31:
        return None

    alert_level = _map_level(scoring.risk_level)
    message = _build_alert_message(scoring, entry)

    alert = Alert(
        level=alert_level,
        message=message,
        score=scoring.risk_score,
        ip=str(entry.get("ip", "")),
        endpoint=str(entry.get("endpoint", "")),
        techniques=json.dumps(scoring.techniques),
        owasp_ref=scoring.owasp_ref,
        log_id=log_id,
    )

    db.add(alert)
    await db.flush()  # Obtenir l'ID avant le commit
    await db.commit()
    await db.refresh(alert)

    log.info(
        "alert_created",
        alert_id=alert.id,
        level=alert.level.value,
        score=alert.score,
        techniques=scoring.techniques,
    )

    # Dispatch WebSocket (best-effort, non bloquant)
    await _dispatch_ws_alert(alert, entry, scoring)

    return alert


async def _dispatch_ws_alert(
    alert: Alert,
    entry: dict[str, Any],
    scoring: ScoringResult,
) -> None:
    """
    Envoie l'alerte aux clients WebSocket connectés.
    Les rooms filtrées par rôle sont gérées dans ConnectionManager.
    """
    if _ws_manager is None:
        return

    ws_payload = {
        "type": "ALERT",
        "level": alert.level.value,
        "message": alert.message,
        "score": alert.score,
        "ip": alert.ip,
        "endpoint": alert.endpoint,
        "techniques": scoring.techniques,
        "owasp_ref": alert.owasp_ref,
        "timestamp": datetime.now(UTC).isoformat(),
        "alert_id": alert.id,
    }

    try:
        await _ws_manager.broadcast(json.dumps(ws_payload), min_level=alert.level)
    except Exception as exc:  # noqa: BLE001
        log.error("ws_dispatch_failed", error=str(exc), alert_id=alert.id)