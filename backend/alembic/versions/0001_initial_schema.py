"""Initial schema — toutes les tables SOC

Revision ID: 0001
Revises:
Create Date: 2026-01-01 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Table users ──────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("hashed_password", sa.String(256), nullable=False),
        sa.Column(
            "role",
            sa.Enum("admin", "analyst", "viewer", name="userrole"),
            nullable=False,
            server_default="viewer",
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
        sa.UniqueConstraint("username"),
    )
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_username", "users", ["username"])

    # ── Table logs ──────────────────────────────────────────────────────
    op.create_table(
        "logs",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("endpoint", sa.String(512), nullable=False),
        sa.Column(
            "method",
            sa.Enum("GET", "POST", "PUT", "DELETE", "PATCH", name="httpmethod"),
            nullable=False,
        ),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("response_time", sa.Float(), nullable=False),
        sa.Column("requests_per_minute", sa.Float(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("anomaly", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("user_agent", sa.String(256), nullable=True),
        sa.Column("user_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_logs_ip_timestamp", "logs", ["ip", "timestamp"])
    op.create_index("ix_logs_timestamp", "logs", ["timestamp"])
    op.create_index("ix_logs_user_id", "logs", ["user_id"])

    # ── Table alerts ─────────────────────────────────────────────────────
    op.create_table(
        "alerts",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column(
            "level",
            sa.Enum("LOW", "MEDIUM", "HIGH", name="alertlevel"),
            nullable=False,
        ),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("ip", sa.String(45), nullable=True),
        sa.Column("endpoint", sa.String(512), nullable=True),
        sa.Column("techniques", sa.Text(), nullable=True),
        sa.Column("owasp_ref", sa.String(32), nullable=True),
        sa.Column("acknowledged", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("acknowledged_by", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("log_id", sa.BigInteger(), sa.ForeignKey("logs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alerts_level", "alerts", ["level"])
    op.create_index("ix_alerts_created_at", "alerts", ["created_at"])

    # ── Table audit_logs (append-only) ────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action", sa.String(256), nullable=False),
        sa.Column("resource", sa.String(512), nullable=False),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("user_agent", sa.String(256), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])

    # ── Trigger append-only audit_logs (OWASP A09) ────────────────────────
    op.execute("""
        CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'Les audit_logs sont en lecture seule après insertion.';
        END;
        $$ LANGUAGE plpgsql;
    """)

    op.execute("""
        CREATE TRIGGER audit_logs_immutable
            BEFORE UPDATE OR DELETE ON audit_logs
            FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_modification();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_logs_immutable ON audit_logs;")
    op.execute("DROP FUNCTION IF EXISTS prevent_audit_log_modification;")
    op.drop_table("audit_logs")
    op.drop_table("alerts")
    op.drop_table("logs")
    op.drop_table("users")
    op.execute("DROP TYPE IF EXISTS alertlevel;")
    op.execute("DROP TYPE IF EXISTS httpmethod;")
    op.execute("DROP TYPE IF EXISTS userrole;")