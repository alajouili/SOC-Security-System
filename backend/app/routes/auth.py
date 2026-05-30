"""
Auth Routes — Register / Login / Refresh Token.
RS256, bcrypt cost=12, rate limiting, messages d'erreur non différenciés (OWASP A07).
"""

import os
from datetime import UTC, datetime, timedelta

import bcrypt
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.database import get_db
from app.database.models import User, UserRole
from app.middleware.rate_limiter import limiter
from app.schemas.user_schema import TokenResponse, UserLoginRequest, UserOut, UserRegisterRequest
from app.services.jwt_handler import create_access_token, create_refresh_token, verify_token

log = structlog.get_logger(__name__)
router = APIRouter()

_BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))


def _hash_password(password: str) -> str:
    """Hash password using bcrypt directly, truncating to 72 bytes."""
    # bcrypt has a 72-byte limit
    truncated = password[:72].encode('utf-8')
    # Truncate the byte representation to 72 bytes
    truncated = truncated[:72]
    salt = bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)
    hashed = bcrypt.hashpw(truncated, salt)
    return hashed.decode('utf-8')


def _verify_password(plain: str, hashed: str) -> bool:
    """Verify password using bcrypt directly."""
    try:
        # bcrypt has a 72-byte limit
        truncated = plain[:72].encode('utf-8')
        truncated = truncated[:72]
        hashed_bytes = hashed.encode('utf-8') if isinstance(hashed, str) else hashed
        return bcrypt.checkpw(truncated, hashed_bytes)
    except Exception as e:
        log.error("password_verify_error", error=str(e))
        return False


@router.post(
    "/register",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    summary="Création de compte",
)
@limiter.limit("5/minute")
async def register(
    request: Request,
    payload: UserRegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Crée un nouveau compte utilisateur.
    Rate-limit : 5 requêtes/minute par IP.
    Le premier utilisateur créé reçoit automatiquement le rôle admin.
    """
    # Vérifier unicité email et username (message générique)
    existing = await db.execute(
        select(User).where(
            (User.email == str(payload.email)) | (User.username == payload.username)
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Un compte avec ces informations existe déjà.",
        )

    # Premier utilisateur = admin
    user_count = await db.execute(select(User))
    is_first_user = user_count.first() is None

    user = User(
        username=payload.username,
        email=str(payload.email),
        hashed_password=_hash_password(payload.password),
        role=UserRole.admin if is_first_user else UserRole.viewer,
        is_active=True,
    )

    db.add(user)
    await db.commit()
    await db.refresh(user)

    log.info("user_registered", user_id=user.id, username=user.username, role=user.role.value)
    return user


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authentification",
)
@limiter.limit("10/minute")
async def login(
    request: Request,
    payload: UserLoginRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Authentifie un utilisateur et retourne un access token JWT RS256 (15min)
    + refresh token httpOnly (7j).

    Les messages d'erreur sont volontairement non différenciés (OWASP A07).
    """
    _GENERIC_ERROR = "Identifiants incorrects."

    result = await db.execute(select(User).where(User.email == str(payload.email)))
    user: User | None = result.scalar_one_or_none()

    # ── Vérification du verrouillage ──────────────────────────────────────
    if user and user.locked_until and user.locked_until > datetime.now(UTC):
        # On retourne la même erreur générique (pas de timing oracle)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_GENERIC_ERROR,
        )

    # ── Vérification des credentials ──────────────────────────────────────
    if not user or not _verify_password(payload.password, user.hashed_password):
        if user:
            # Incrémenter le compteur d'échecs
            new_attempts = user.failed_login_attempts + 1
            locked_until = None

            if new_attempts >= _MAX_FAILED_ATTEMPTS:
                locked_until = datetime.now(UTC) + timedelta(minutes=_LOCKOUT_MINUTES)
                log.warning(
                    "account_locked",
                    user_id=user.id,
                    attempts=new_attempts,
                    locked_until=locked_until.isoformat(),
                )

            await db.execute(
                update(User)
                .where(User.id == user.id)
                .values(failed_login_attempts=new_attempts, locked_until=locked_until)
            )
            await db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_GENERIC_ERROR,
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_GENERIC_ERROR,
        )

    # ── Réinitialisation des compteurs ────────────────────────────────────
    await db.execute(
        update(User)
        .where(User.id == user.id)
        .values(failed_login_attempts=0, locked_until=None, last_login=datetime.now(UTC))
    )
    await db.commit()

    # ── Génération des tokens ─────────────────────────────────────────────
    access_token = create_access_token(user_id=user.id, role=user.role.value)
    refresh_token = create_refresh_token(user_id=user.id)

    # Refresh token en cookie httpOnly (non accessible JS)
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=7 * 24 * 3600,
        path="/auth/refresh",
    )

    log.info("user_login_success", user_id=user.id, username=user.username)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 15 * 60,
    }


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Renouvellement du token",
)
async def refresh_token(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Renouvelle l'access token via le refresh token httpOnly.
    Le refresh token est lu depuis le cookie sécurisé.
    """
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token manquant.",
        )

    payload = verify_token(token, expected_type="refresh")
    user_id = int(payload["sub"])

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Utilisateur introuvable ou désactivé.",
        )

    new_access_token = create_access_token(user_id=user.id, role=user.role.value)
    log.info("token_refreshed", user_id=user.id)

    return {
        "access_token": new_access_token,
        "token_type": "bearer",
        "expires_in": 15 * 60,
    }