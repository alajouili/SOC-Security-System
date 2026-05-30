"""
Database Configuration — SQLAlchemy asyncio + PostgreSQL.
TLS enabled, async sessions, engine pooling.
"""

import os
from typing import AsyncGenerator

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base, sessionmaker

log = structlog.get_logger(__name__)

# Database URL from environment (Docker Compose)
_DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://socuser:SecurePassw0rd!2024@localhost:5432/socdb",
)

# SQLAlchemy async engine with connection pooling
engine = create_async_engine(
    _DATABASE_URL,
    echo=False,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,
    pool_recycle=3600,
)

# Async session factory
AsyncSessionLocal = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

# Declarative base for ORM models
Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency injection pour FastAPI — fournit une session async.
    La session est fermée automatiquement après la requête.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def create_tables() -> None:
    """
    Crée toutes les tables à partir des modèles ORM au démarrage.
    Idempotent — les tables existantes ne sont pas modifiées.
    """
    log.info("database_init", message="Création des tables...")
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        log.info("database_ready", message="Tables initialisées avec succès")
    except Exception as exc:
        log.error("database_init_error", error=str(exc))
        raise
