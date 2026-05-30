"""
Permissions — RBAC (Role-Based Access Control) — OWASP A01.
Décorateurs et dépendances FastAPI pour la vérification des rôles.
"""

from fastapi import Depends, HTTPException, status

from app.database.models import User, UserRole
from app.services.jwt_handler import get_current_user


def require_role(*roles: UserRole):
    """
    Dépendance FastAPI — vérifie que l'utilisateur courant possède l'un des rôles requis.

    Usage:
        @router.get("/admin-only")
        async def admin_endpoint(user: User = Depends(require_role(UserRole.admin))):
            ...
    """

    async def dependency(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permissions insuffisantes pour accéder à cette ressource.",
            )
        return current_user

    return dependency


# ── Alias pratiques ──────────────────────────────────────────────────────────

def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Réservé aux administrateurs."""
    if current_user.role != UserRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Accès réservé aux administrateurs.",
        )
    return current_user


def require_analyst_or_above(current_user: User = Depends(get_current_user)) -> User:
    """Réservé aux analysts et admins."""
    if current_user.role not in (UserRole.admin, UserRole.analyst):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Accès réservé aux analystes et administrateurs.",
        )
    return current_user


def require_authenticated(current_user: User = Depends(get_current_user)) -> User:
    """Tout utilisateur authentifié (viewer inclus)."""
    return current_user