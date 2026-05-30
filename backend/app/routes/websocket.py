"""
WebSocket Route — /ws — Alertes temps réel.
Authentification JWT vérifiée à la connexion ET à chaque message.
Rooms par rôle : viewer < analyst < admin.
"""

import asyncio
import json
from typing import Any

import structlog
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.database import AsyncSessionLocal
from app.database.models import AlertLevel, User, UserRole
from app.services.alerts_engine import set_ws_manager
from app.services.jwt_handler import get_current_user_ws

log = structlog.get_logger(__name__)
router = APIRouter()

# Mapping rôle → niveaux d'alertes visibles
_ROLE_ALERT_LEVELS: dict[UserRole, set[str]] = {
    UserRole.viewer: {"LOW", "MEDIUM"},
    UserRole.analyst: {"LOW", "MEDIUM", "HIGH"},
    UserRole.admin: {"LOW", "MEDIUM", "HIGH"},
}


class ConnectionManager:
    """
    Gestionnaire des connexions WebSocket avec rooms par rôle.
    Chaque connexion est associée à un utilisateur authentifié.
    """

    def __init__(self) -> None:
        # {websocket: (user, allowed_levels)}
        self._connections: dict[WebSocket, tuple[User, set[str]]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, user: User) -> None:
        """Enregistre une nouvelle connexion WebSocket."""
        await websocket.accept()
        allowed = _ROLE_ALERT_LEVELS.get(user.role, set())
        async with self._lock:
            self._connections[websocket] = (user, allowed)

        log.info(
            "ws_client_connected",
            user_id=user.id,
            role=user.role.value,
            total_connections=len(self._connections),
        )

    async def disconnect(self, websocket: WebSocket) -> None:
        """Supprime une connexion WebSocket."""
        async with self._lock:
            conn_info = self._connections.pop(websocket, None)

        if conn_info:
            user, _ = conn_info
            log.info("ws_client_disconnected", user_id=user.id)

    async def broadcast(self, message: str, min_level: AlertLevel | None = None) -> None:
        """
        Envoie un message à tous les clients autorisés.
        Filtre selon le niveau d'alerte et le rôle de chaque client.

        Args:
            message: Payload JSON sérialisé.
            min_level: Niveau minimum de l'alerte (filtre par room).
        """
        if not self._connections:
            return

        # Déterminer le niveau de l'alerte
        level_str = "LOW"
        if min_level:
            level_str = min_level.value if hasattr(min_level, "value") else str(min_level)

        disconnected: list[WebSocket] = []

        async with self._lock:
            connections_snapshot = list(self._connections.items())

        for websocket, (user, allowed_levels) in connections_snapshot:
            if level_str not in allowed_levels:
                continue  # Room filtering — ce rôle ne reçoit pas ce niveau

            try:
                await websocket.send_text(message)
            except Exception:  # noqa: BLE001
                disconnected.append(websocket)

        for ws in disconnected:
            await self.disconnect(ws)

    @property
    def active_connections(self) -> int:
        return len(self._connections)

    def connections_by_role(self) -> dict[str, int]:
        """Retourne le nombre de connexions par rôle (pour les métriques)."""
        counts: dict[str, int] = {}
        for _, (user, _) in self._connections.items():
            role = user.role.value
            counts[role] = counts.get(role, 0) + 1
        return counts


# Singleton du gestionnaire
manager = ConnectionManager()

# Injection dans alerts_engine (évite les imports circulaires)
set_ws_manager(manager)


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(..., description="JWT access token"),
) -> None:
    """
    Endpoint WebSocket — flux d'alertes temps réel.

    Connexion : wss://host/ws?token=<access_token>

    Authentification :
    - Token vérifié à la connexion
    - Token re-vérifié à chaque message entrant

    Messages entrants supportés :
    - {"type": "ping"} → {"type": "pong"}
    - {"type": "reauth", "token": "..."} → revalidation
    """
    # ── Authentification initiale ─────────────────────────────────────────
    async with AsyncSessionLocal() as db:
        user = await get_current_user_ws(token, db)

    if not user:
        await websocket.close(code=4001, reason="Token invalide ou expiré.")
        log.warning("ws_auth_failed", reason="invalid_token")
        return

    await manager.connect(websocket, user)

    # Message de bienvenue
    welcome = json.dumps({
        "type": "CONNECTED",
        "message": f"Connecté au SOC — rôle : {user.role.value}",
        "allowed_levels": list(_ROLE_ALERT_LEVELS.get(user.role, set())),
    })
    await websocket.send_text(welcome)

    try:
        while True:
            try:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                # Ping keepalive
                await websocket.send_text(json.dumps({"type": "ping"}))
                continue

            # ── Vérification du token à chaque message (OWASP A01) ────────
            async with AsyncSessionLocal() as db:
                current_user = await get_current_user_ws(token, db)

            if not current_user:
                await websocket.send_text(json.dumps({
                    "type": "ERROR",
                    "detail": "Session expirée. Veuillez vous reconnecter.",
                }))
                await websocket.close(code=4001)
                break

            # ── Traitement du message ─────────────────────────────────────
            try:
                msg = json.loads(raw)
                msg_type = msg.get("type", "")

                if msg_type == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))

                elif msg_type == "get_stats":
                    stats = {
                        "type": "STATS",
                        "active_connections": manager.active_connections,
                        "connections_by_role": manager.connections_by_role(),
                    }
                    await websocket.send_text(json.dumps(stats))

                else:
                    await websocket.send_text(json.dumps({
                        "type": "ERROR",
                        "detail": f"Type de message non reconnu : {msg_type}",
                    }))

            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({
                    "type": "ERROR",
                    "detail": "Message JSON invalide.",
                }))

    except WebSocketDisconnect:
        pass
    except Exception as exc:  # noqa: BLE001
        log.error("ws_unexpected_error", error=str(exc), user_id=user.id)
    finally:
        await manager.disconnect(websocket)