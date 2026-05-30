"""
JWT Handler — RS256 (paire RSA 2048 bits) — OWASP A02 / A07.
Gestion des access tokens (15min) et refresh tokens (7j httpOnly).
La clé privée ne quitte jamais ce service.
"""

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.database import get_db
from app.database.models import User

log = structlog.get_logger(__name__)

_ALGORITHM = os.getenv("JWT_ALGORITHM", "RS256")
_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
_REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

_bearer_scheme = HTTPBearer()


def _load_key(path_env: str, key_type: str) -> str:
    """
    Charge une clé PEM depuis le chemin défini dans l'environnement.
    Lève une erreur critique si la clé est absente.
    """
    key_path = os.getenv(path_env)
    if not key_path:
        raise RuntimeError(f"Variable d'environnement {path_env} non définie.")

    path = Path(key_path)
    if not path.exists():
        raise FileNotFoundError(f"Clé {key_type} introuvable : {key_path}")

    return path.read_text(encoding="utf-8").strip()


def _get_private_key() -> str:
    return _load_key("JWT_PRIVATE_KEY_PATH", "privée RS256")


def _get_public_key() -> str:
    return _load_key("JWT_PUBLIC_KEY_PATH", "publique RS256")


def create_access_token(user_id: int, role: str) -> str:
    """
    Crée un access token JWT signé RS256 avec expiration courte (15min).

    Args:
        user_id: Identifiant de l'utilisateur.
        role: Rôle RBAC de l'utilisateur.

    Returns:
        Token JWT signé.
    """
    expire = datetime.now(UTC) + timedelta(minutes=_ACCESS_TOKEN_EXPIRE_MINUTES)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "role": role,
        "type": "access",
        "exp": expire,
        "iat": datetime.now(UTC),
    }
    return jwt.encode(payload, _get_private_key(), algorithm=_ALGORITHM)


def create_refresh_token(user_id: int) -> str:
    """
    Crée un refresh token JWT signé RS256 avec expiration longue (7j).

    Args:
        user_id: Identifiant de l'utilisateur.

    Returns:
        Token JWT signé.
    """
    expire = datetime.now(UTC) + timedelta(days=_REFRESH_TOKEN_EXPIRE_DAYS)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "type": "refresh",
        "exp": expire,
        "iat": datetime.now(UTC),
    }
    return jwt.encode(payload, _get_private_key(), algorithm=_ALGORITHM)


def verify_token(token: str, expected_type: str = "access") -> dict[str, Any]:
    """
    Vérifie et décode un token JWT RS256.

    Args:
        token: Token JWT à vérifier.
        expected_type: Type attendu ("access" ou "refresh").

    Returns:
        Payload décodé.

    Raises:
        HTTPException 401 si le token est invalide ou expiré.
    """
    try:
        payload = jwt.decode(token, _get_public_key(), algorithms=[_ALGORITHM])

        token_type = payload.get("type")
        if token_type != expected_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Type de token invalide.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return payload

    except JWTError as exc:
        log.warning("jwt_verification_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide ou expiré.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Dépendance FastAPI — extrait et vérifie l'utilisateur depuis le Bearer token.

    Returns:
        Instance User authentifiée.

    Raises:
        HTTPException 401 si token invalide.
        HTTPException 403 si compte désactivé.
    """
    from sqlalchemy import select

    payload = verify_token(credentials.credentials, expected_type="access")
    user_id_str = payload.get("sub")

    if not user_id_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token malformé.",
        )

    try:
        user_id = int(user_id_str)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token malformé.",
        ) from exc

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Utilisateur introuvable.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Compte désactivé.",
        )

    return user


async def get_current_user_ws(token: str, db: AsyncSession) -> User | None:
    """
    Version WebSocket de get_current_user (sans dépendance Depends).
    Utilisée pour l'authentification lors de la connexion WS.

    Args:
        token: Token JWT extrait du query param ou header.
        db: Session de base de données.

    Returns:
        Instance User ou None si authentification échouée.
    """
    from sqlalchemy import select

    try:
        payload = verify_token(token, expected_type="access")
        user_id = int(payload["sub"])

        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

        if user and user.is_active:
            return user
        return None

    except Exception:  # noqa: BLE001
        return None