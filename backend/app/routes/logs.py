"""
Logs Route — GET /logs — Historique paginé avec filtres.
Filtres : ip, level (anomaly/normal), date_range, endpoint.
Principle du moindre privilège : un viewer ne voit que ses propres logs.
"""

from datetime import datetime
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.database import get_db
from app.database.models import Log, User, UserRole
from app.middleware.rate_limiter import limiter
from app.schemas.log_schema import LogListResponse
from app.security.permissions import require_authenticated

log = structlog.get_logger(__name__)
router = APIRouter()


@router.get(
    "/logs",
    response_model=LogListResponse,
    summary="Historique des logs paginé",
)
@limiter.limit("30/minute")
async def get_logs(
    request: Request,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    ip: str | None = Query(default=None, max_length=45),
    anomaly_only: bool = Query(default=False),
    date_from: datetime | None = Query(default=None),
    date_to: datetime | None = Query(default=None),
    min_score: float | None = Query(default=None, ge=0, le=100),
    current_user: User = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
) -> LogListResponse:
    """
    Retourne les logs paginés avec filtres optionnels.

    Contrôle d'accès (OWASP A01) :
    - viewer : voit uniquement ses propres logs
    - analyst/admin : voit tous les logs
    """
    query = select(Log)

    # ── Isolation par rôle ────────────────────────────────────────────────
    if current_user.role == UserRole.viewer:
        query = query.where(Log.user_id == current_user.id)

    # ── Filtres optionnels ────────────────────────────────────────────────
    if ip:
        query = query.where(Log.ip == ip)

    if anomaly_only:
        query = query.where(Log.anomaly == True)  # noqa: E712

    if date_from:
        query = query.where(Log.timestamp >= date_from)

    if date_to:
        query = query.where(Log.timestamp <= date_to)

    if min_score is not None:
        query = query.where(Log.risk_score >= min_score)

    # ── Comptage total (pour la pagination) ───────────────────────────────
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    # ── Pagination ────────────────────────────────────────────────────────
    offset = (page - 1) * page_size
    query = query.order_by(Log.timestamp.desc()).offset(offset).limit(page_size)

    result = await db.execute(query)
    logs = result.scalars().all()

    pages = max(1, -(-total // page_size))  # Division entière par excès

    return LogListResponse(
        items=list(logs),
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )