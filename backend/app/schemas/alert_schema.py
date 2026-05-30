"""
Alert Schemas — Pydantic v2.
Sérialization des alertes avec pagination.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.database.models import AlertLevel


class AlertOut(BaseModel):
    """Représentation publique d'une alerte."""

    id: int
    level: AlertLevel
    message: str
    score: float
    ip: str | None
    endpoint: str | None
    techniques: list[str] | None = None
    owasp_ref: str | None
    acknowledged: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertListResponse(BaseModel):
    """Réponse paginée pour GET /alerts."""

    items: list[AlertOut]
    total: int
    page: int
    page_size: int
    pages: int


class AlertStats(BaseModel):
    """Statistiques agrégées pour GET /stats."""

    total_analyzed: int
    total_alerts: int
    high_count: int
    medium_count: int
    low_count: int
    avg_risk_score: float
    top_ips: list[dict[str, Any]]
    top_endpoints: list[dict[str, Any]]
    anomaly_rate: float


class AlertAcknowledgeRequest(BaseModel):
    """Corps de la requête d'acquittement d'alerte."""

    acknowledged: bool = True
    