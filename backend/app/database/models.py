"""
ORM Models — SQLAlchemy declarative models.
User, Log, Alert, AuditLog tables with constraints.
"""

from datetime import UTC, datetime
from enum import Enum

from sqlalchemy import Boolean, DateTime, Enum as SQLEnum
from sqlalchemy import Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.database import Base


class UserRole(str, Enum):
    """Rôles RBAC — hiérarchie : viewer < analyst < admin."""
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class HttpMethod(str, Enum):
    """Méthodes HTTP acceptées."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"


class AlertLevel(str, Enum):
    """Niveaux de sévérité des alertes."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class User(Base):
    """
    Utilisateur du système SOC.
    Rôle-based access control, account lockout, audit trail.
    """
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        SQLEnum(UserRole), default=UserRole.viewer, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Account lockout after failed login attempts
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Timestamps
    last_login: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    # Relationships
    logs: Mapped[list["Log"]] = relationship(
        "Log", back_populates="user", cascade="all, delete-orphan"
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        "AuditLog", back_populates="user", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_user_email", "email"),
        Index("idx_user_username", "username"),
    )


class Log(Base):
    """
    HTTP log entry analysé.
    Contient le score de risque, niveau d'anomalie, et associations.
    """
    __tablename__ = "logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False)
    method: Mapped[HttpMethod] = mapped_column(
        SQLEnum(HttpMethod), nullable=False
    )
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    response_time: Mapped[float] = mapped_column(Float, nullable=False)
    requests_per_minute: Mapped[float] = mapped_column(Float, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    anomaly: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    user_agent: Mapped[str] = mapped_column(String(256), nullable=True)

    # Foreign key
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False, index=True
    )

    # Timestamps
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="logs")
    alert: Mapped["Alert"] = relationship(
        "Alert", back_populates="log", uselist=False, cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_log_ip", "ip"),
        Index("idx_log_timestamp", "timestamp"),
        Index("idx_log_user_id", "user_id"),
        Index("idx_log_risk_score", "risk_score"),
    )


class Alert(Base):
    """
    Alerte de sécurité générée si risk_score ≥ 31.
    Peut être acquittée par analyst/admin.
    """
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    level: Mapped[AlertLevel] = mapped_column(
        SQLEnum(AlertLevel), nullable=False, index=True
    )
    message: Mapped[str] = mapped_column(String(512), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    endpoint: Mapped[str | None] = mapped_column(String(512), nullable=True)
    techniques: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON serialized
    owasp_ref: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Acknowledgement
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    acknowledged_by: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Foreign key to Log (optional)
    log_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("logs.id"), nullable=True
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False, index=True
    )

    # Relationships
    log: Mapped["Log"] = relationship("Log", back_populates="alert")

    __table_args__ = (
        Index("idx_alert_level", "level"),
        Index("idx_alert_created_at", "created_at"),
        Index("idx_alert_acknowledged", "acknowledged"),
    )


class AuditLog(Base):
    """
    Journal d'audit — append-only.
    Toutes les actions enregistrées avec timestamp et IP.
    """
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(256), nullable=False)
    resource: Mapped[str] = mapped_column(String(512), nullable=False)
    ip: Mapped[str] = mapped_column(String(45), nullable=False)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)  # success/failure

    # Timestamp (append-only)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False, index=True
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="audit_logs")

    __table_args__ = (
        Index("idx_audit_log_user_id", "user_id"),
        Index("idx_audit_log_created_at", "created_at"),
        Index("idx_audit_log_action", "action"),
    )
