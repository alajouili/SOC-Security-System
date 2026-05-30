# ── Stage 1 : Builder ─────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Dépendances système minimales
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copie et installation des dépendances dans un virtualenv
COPY backend/requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip setuptools wheel && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt


# ── Stage 2 : Production ──────────────────────────────────────────────────
FROM python:3.12-slim AS production

LABEL maintainer="SOC Team" \
      version="2.0.0" \
      description="SOC Security System — OWASP Top 10 2021"

# Dépendances runtime uniquement
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libffi8 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Utilisateur non-root (uid 1000) — OWASP A05
RUN groupadd --gid 1000 socapp && \
    useradd --uid 1000 --gid 1000 --no-create-home --shell /bin/false socapp

# Virtualenv depuis le builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Copie du code applicatif
COPY --chown=socapp:socapp backend/app/ ./app/
COPY --chown=socapp:socapp backend/data/ ./data/
COPY --chown=socapp:socapp backend/scripts/ ./scripts/
COPY --chown=socapp:socapp backend/monitoring/ ./monitoring/
COPY --chown=socapp:socapp backend/alembic/ ./alembic/
COPY --chown=socapp:socapp backend/alembic/alembic.ini .

# Répertoire pour le modèle ML
RUN mkdir -p /app/model && chown socapp:socapp /app/model

# Variables d'environnement par défaut (surchargées par docker-compose)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ENVIRONMENT=production \
    LOG_LEVEL=INFO

# Port exposé
EXPOSE 8000

# Passage à l'utilisateur non-root
USER socapp

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Point d'entrée
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "4", \
     "--no-access-log"]