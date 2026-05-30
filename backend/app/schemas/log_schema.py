"""
Log Schemas — Validation stricte Pydantic v2.
Contraintes de champs conformes à la spécification SOC v2.0.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, IPvAnyAddress, field_validator


class HttpMethodEnum(str, Enum):
    """Méthodes HTTP acceptées — validation stricte."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"


class LogEntry(BaseModel):
    """
    Entrée de log à analyser.
    Toutes les contraintes de validation sont définies ici.
    Les champs string sont ensuite sanitisés dans input_sanitizer.py.
    """

    ip: IPvAnyAddress
    endpoint: str = Field(..., max_length=512)
    method: HttpMethodEnum
    status_code: int = Field(..., ge=100, le=599)
    requests_per_minute: float = Field(..., ge=0.0, le=10000.0)
    response_time: float = Field(..., ge=0.0, description="Temps de réponse en millisecondes")
    user_agent: str = Field(..., max_length=256)
    timestamp: datetime

    @field_validator("timestamp")
    @classmethod
    def validate_utc_timestamp(cls, v: datetime) -> datetime:
        """Vérifie que le timestamp est en UTC (timezone-aware)."""
        if v.tzinfo is None:
            raise ValueError("Le timestamp doit être timezone-aware (UTC obligatoire).")
        return v

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint_no_null(cls, v: str) -> str:
        """Rejette les endpoints contenant des octets nuls."""
        if "\x00" in v:
            raise ValueError("L'endpoint ne peut pas contenir d'octets nuls.")
        return v

    model_config = {"str_strip_whitespace": True}


class LogEntryOut(BaseModel):
    """Log enrichi retourné après analyse."""

    id: int
    ip: str
    endpoint: str
    method: str
    status_code: int
    response_time: float
    requests_per_minute: float
    risk_score: float
    anomaly: bool
    timestamp: datetime
    created_at: datetime

    model_config = {"from_attributes": True}


class LogListResponse(BaseModel):
    """Réponse paginée pour GET /logs."""

    items: list[LogEntryOut]
    total: int
    page: int
    page_size: int
    pages: int