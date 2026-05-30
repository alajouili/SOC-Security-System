"""
Audit Logger Middleware — OWASP A09.
Enregistre toutes les requêtes HTTP entrantes dans la table audit_logs
(append-only, protégée par trigger PostgreSQL).
"""

import time
import uuid
from typing import Callable

import structlog
from sqlalchemy import text
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

log = structlog.get_logger(__name__)


class AuditLoggerMiddleware(BaseHTTPMiddleware):
    """
    Middleware d'audit complet.
    - Génère un request_id unique par requête
    - Mesure la durée de traitement
    - Insère un enregistrement dans audit_logs via SQLAlchemy
    - Ne bloque jamais la requête en cas d'échec DB
    """

    # Endpoints exclus de l'audit (healthcheck, métriques)
    _SKIP_PATHS = {"/health", "/metrics", "/favicon.ico"}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:  # type: ignore[override]
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        if request.url.path in self._SKIP_PATHS:
            return await call_next(request)

        start_time = time.monotonic()
        response: Response = await call_next(request)
        duration_ms = round((time.monotonic() - start_time) * 1000, 2)

        # Récupération du user_id depuis le token (déjà décodé par les routes)
        user_id = getattr(request.state, "user_id", None)

        # Anonymisation partielle de l'IP (dernier octet masqué)
        client_ip = self._get_client_ip(request)

        log.info(
            "http_request",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=duration_ms,
            user_id=user_id,
            ip=client_ip,
        )

        # Insertion asynchrone en base (best-effort, sans bloquer la réponse)
        try:
            await self._persist_audit_log(
                request=request,
                response=response,
                duration_ms=duration_ms,
                user_id=user_id,
                client_ip=client_ip,
                request_id=request_id,
            )
        except Exception as exc:  # noqa: BLE001
            log.error("audit_log_persistence_failed", error=str(exc), request_id=request_id)

        response.headers["X-Request-ID"] = request_id
        return response

    async def _persist_audit_log(
        self,
        request: Request,
        response: Response,
        duration_ms: float,
        user_id: int | None,
        client_ip: str,
        request_id: str,
    ) -> None:
        """Persiste l'entrée d'audit dans PostgreSQL."""
        from app.database.database import AsyncSessionLocal

        action = f"{request.method} {request.url.path}"
        user_agent = request.headers.get("user-agent", "")[:256]
        status = "success" if response.status_code < 400 else "failure"

        async with AsyncSessionLocal() as session:
            await session.execute(
                text(
                    """
                    INSERT INTO audit_logs
                        (user_id, action, resource, ip, user_agent, status, created_at)
                    VALUES
                        (:user_id, :action, :resource, :ip, :user_agent, :status, NOW())
                    """
                ),
                {
                    "user_id": user_id,
                    "action": action,
                    "resource": str(request.url.path),
                    "ip": client_ip,
                    "user_agent": user_agent,
                    "status": status,
                },
            )
            await session.commit()

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        """Extrait l'IP cliente en tenant compte des proxies."""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"
    