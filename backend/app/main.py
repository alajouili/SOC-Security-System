"""
SOC System — Main FastAPI Application
Entrypoint principal avec middlewares de sécurité, CORS strict et routage.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
import uvicorn
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.database.database import create_tables, engine
from app.middleware.audit_logger import AuditLoggerMiddleware
from app.middleware.rate_limiter import limiter
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.routes import alerts, analyze, auth, logs, websocket

log = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Gestion du cycle de vie de l'application."""
    log.info("soc_startup", message="Démarrage du système SOC v2.0")
    await create_tables()
    yield
    log.info("soc_shutdown", message="Arrêt du système SOC")
    await engine.dispose()


def create_application() -> FastAPI:
    """Factory principale — crée et configure l'instance FastAPI."""

    import os

    env = os.getenv("ENVIRONMENT", "production")
    is_dev = env == "development"

    app = FastAPI(
        title="SOC Security System v2.0",
        description="Security Operations Center — Détection d'anomalies OWASP Top 10 2021",
        version="2.0.0",
        docs_url="/docs" if is_dev else None,
        redoc_url="/redoc" if is_dev else None,
        openapi_url="/openapi.json" if is_dev else None,
        lifespan=lifespan,
    )

    # ── Rate limiter (slowapi) ──────────────────────────────────────────────
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    # ── CORS strict — jamais de wildcard en production ──────────────────────
    import json

    cors_origins_raw = os.getenv("CORS_ORIGINS", '["http://localhost:3000"]')
    try:
        cors_origins = json.loads(cors_origins_raw)
    except (json.JSONDecodeError, ValueError):
        cors_origins = ["http://localhost:3000"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
    )

    # ── Security headers (CSP, HSTS, X-Frame-Options…) ─────────────────────
    app.add_middleware(SecurityHeadersMiddleware)

    # ── Audit logger — toutes les requêtes ─────────────────────────────────
    app.add_middleware(AuditLoggerMiddleware)

    # ── Routes ─────────────────────────────────────────────────────────────
    app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
    app.include_router(analyze.router, tags=["Analysis"])
    app.include_router(logs.router, tags=["Logs"])
    app.include_router(alerts.router, tags=["Alerts"])
    app.include_router(websocket.router, tags=["WebSocket"])

    # ── Métriques Prometheus (accès restreint réseau) ──────────────────────
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)

    # ── Healthcheck ────────────────────────────────────────────────────────
    @app.get("/health", include_in_schema=False)
    async def health_check() -> dict:
        return {"status": "ok", "version": "2.0.0"}

    # ── Gestionnaire d'erreurs génériques ──────────────────────────────────
    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        log.error("unhandled_exception", path=str(request.url), error=str(exc))
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Une erreur interne est survenue."},
        )

    return app


app = create_application()

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        workers=4,
        log_config=None,
    )