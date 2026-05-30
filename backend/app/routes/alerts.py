"""
Alerts Routes — GET /alerts + /stats + PATCH acknowledge.
Filtres, pagination, statistiques agrégées.
"""

import json
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import case, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.database import get_db
from app.database.models import Alert, AlertLevel, Log, User, UserRole
from app.middleware.rate_limiter import limiter
from app.schemas.alert_schema import (
    AlertAcknowledgeRequest,
    AlertListResponse,
    AlertOut,
    AlertStats,
)
from app.security.permissions import require_analyst_or_above, require_authenticated

log = structlog.get_logger(__name__)
router = APIRouter()


@router.get(
    "/alerts",
    response_model=AlertListResponse,
    summary="Liste des alertes filtrables",
)
@limiter.limit("30/minute")
async def get_alerts(
    request: Request,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    level: AlertLevel | None = Query(default=None),
    owasp_ref: str | None = Query(default=None, max_length=32),
    acknowledged: bool | None = Query(default=None),
    current_user: User = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
) -> AlertListResponse:
    """
    Retourne les alertes paginées et filtrables.
    Viewer ne voit que les alertes LOW et MEDIUM (pas les HIGH).
    """
    query = select(Alert)

    # Restriction par rôle
    if current_user.role == UserRole.viewer:
        query = query.where(Alert.level.in_([AlertLevel.LOW, AlertLevel.MEDIUM]))

    if level:
        query = query.where(Alert.level == level)

    if owasp_ref:
        query = query.where(Alert.owasp_ref == owasp_ref)

    if acknowledged is not None:
        query = query.where(Alert.acknowledged == acknowledged)

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar_one()

    offset = (page - 1) * page_size
    query = query.order_by(Alert.created_at.desc()).offset(offset).limit(page_size)

    result = await db.execute(query)
    alerts = result.scalars().all()

    # Désérialisation des techniques
    alert_outs = []
    for a in alerts:
        techniques = None
        if a.techniques:
            try:
                techniques = json.loads(a.techniques)
            except (json.JSONDecodeError, TypeError):
                techniques = []

        alert_outs.append(
            AlertOut(
                id=a.id,
                level=a.level,
                message=a.message,
                score=a.score,
                ip=a.ip,
                endpoint=a.endpoint,
                techniques=techniques,
                owasp_ref=a.owasp_ref,
                acknowledged=a.acknowledged,
                created_at=a.created_at,
            )
        )

    pages = max(1, -(-total // page_size))
    return AlertListResponse(items=alert_outs, total=total, page=page, page_size=page_size, pages=pages)


@router.patch(
    "/alerts/{alert_id}/acknowledge",
    response_model=AlertOut,
    summary="Acquitter une alerte",
)
async def acknowledge_alert(
    alert_id: int,
    payload: AlertAcknowledgeRequest,
    current_user: User = Depends(require_analyst_or_above),
    db: AsyncSession = Depends(get_db),
) -> AlertOut:
    """
    Acquitte une alerte — analyst et admin uniquement.
    Le contenu de l'alerte reste immuable (seul acknowledged change).
    """
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alerte introuvable.")

    await db.execute(
        update(Alert)
        .where(Alert.id == alert_id)
        .values(acknowledged=payload.acknowledged, acknowledged_by=current_user.id)
    )
    await db.commit()
    await db.refresh(alert)

    log.info("alert_acknowledged", alert_id=alert_id, by_user=current_user.id)

    techniques = None
    if alert.techniques:
        try:
            techniques = json.loads(alert.techniques)
        except (json.JSONDecodeError, TypeError):
            techniques = []

    return AlertOut(
        id=alert.id, level=alert.level, message=alert.message, score=alert.score,
        ip=alert.ip, endpoint=alert.endpoint, techniques=techniques,
        owasp_ref=alert.owasp_ref, acknowledged=alert.acknowledged,
        created_at=alert.created_at,
    )


@router.get(
    "/stats",
    response_model=AlertStats,
    summary="Métriques agrégées SOC",
)
@limiter.limit("30/minute")
async def get_stats(
    request: Request,
    current_user: User = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
) -> AlertStats:
    """Retourne les statistiques agrégées : distribution, top IPs, top endpoints."""

    # Totaux logs
    total_logs_result = await db.execute(select(func.count(Log.id)))
    total_analyzed = total_logs_result.scalar_one() or 0

    # Totaux alertes par niveau
    alert_counts = await db.execute(
        select(
            Alert.level,
            func.count(Alert.id).label("cnt"),
        ).group_by(Alert.level)
    )
    counts_by_level = {row.level: row.cnt for row in alert_counts}

    high_count = counts_by_level.get(AlertLevel.HIGH, 0)
    medium_count = counts_by_level.get(AlertLevel.MEDIUM, 0)
    low_count = counts_by_level.get(AlertLevel.LOW, 0)
    total_alerts = high_count + medium_count + low_count

    # Score moyen
    avg_result = await db.execute(select(func.avg(Log.risk_score)))
    avg_score = float(avg_result.scalar_one() or 0.0)

    # Taux d'anomalies
    anomaly_count_result = await db.execute(
        select(func.count(Log.id)).where(Log.anomaly == True)  # noqa: E712
    )
    anomaly_count = anomaly_count_result.scalar_one() or 0
    anomaly_rate = (anomaly_count / total_analyzed * 100) if total_analyzed > 0 else 0.0

    # Top 5 IPs
    top_ips_result = await db.execute(
        select(Log.ip, func.count(Log.id).label("cnt"))
        .group_by(Log.ip)
        .order_by(func.count(Log.id).desc())
        .limit(5)
    )
    top_ips = [{"ip": row.ip, "count": row.cnt} for row in top_ips_result]

    # Top 5 endpoints
    top_ep_result = await db.execute(
        select(Log.endpoint, func.count(Log.id).label("cnt"))
        .group_by(Log.endpoint)
        .order_by(func.count(Log.id).desc())
        .limit(5)
    )
    top_endpoints = [{"endpoint": row.endpoint, "count": row.cnt} for row in top_ep_result]

    return AlertStats(
        total_analyzed=total_analyzed,
        total_alerts=total_alerts,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        avg_risk_score=round(avg_score, 2),
        top_ips=top_ips,
        top_endpoints=top_endpoints,
        anomaly_rate=round(anomaly_rate, 2),
    )