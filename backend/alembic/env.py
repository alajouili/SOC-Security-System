"""Alembic environment configuration — migrations asynchrones SQLAlchemy 2.0."""

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

# Import des modèles pour la détection automatique des changements de schéma
from app.database.database import Base
from app.database import models  # noqa: F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# URL depuis l'environnement (surcharge alembic.ini en production)
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    config.get_main_option("sqlalchemy.url"),
)


def run_migrations_offline() -> None:
    """Migrations en mode offline (génération SQL uniquement)."""
    context.configure(
        url=DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Migrations en mode online avec engine asyncpg."""
    connectable = create_async_engine(DATABASE_URL, echo=False)

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Point d'entrée pour les migrations online."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()