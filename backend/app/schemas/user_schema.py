"""
User Schemas — Validation stricte Pydantic v2.
Regex email RFC 5321, force mot de passe, enum rôles.
"""

import re
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.database.models import UserRole

# Expression régulière pour les mots de passe complexes
_PASSWORD_PATTERN = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~]).{12,128}$"
)


class UserRegisterRequest(BaseModel):
    """Schéma de création de compte — validation stricte."""

    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$")
    email: EmailStr
    password: str = Field(..., min_length=12, max_length=128)

    @field_validator("password")
    @classmethod
    def validate_password_complexity(cls, v: str) -> str:
        """Vérifie la complexité : maj, min, chiffre, caractère spécial, ≥12 chars."""
        if not _PASSWORD_PATTERN.match(v):
            raise ValueError(
                "Le mot de passe doit contenir au moins 12 caractères, "
                "une majuscule, une minuscule, un chiffre et un caractère spécial."
            )
        return v


class UserLoginRequest(BaseModel):
    """Schéma de connexion."""

    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)


class TokenResponse(BaseModel):
    """Réponse JWT après authentification réussie."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int  # secondes


class UserOut(BaseModel):
    """Représentation publique d'un utilisateur (sans données sensibles)."""

    id: int
    username: str
    email: str
    role: UserRole
    is_active: bool
    last_login: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class UserRoleUpdate(BaseModel):
    """Mise à jour du rôle — admin uniquement."""

    role: UserRole