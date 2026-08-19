"""Dependances FastAPI : session, utilisateur courant, controle des roles."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.security import decode_access_token
from app.models import User, UserRole

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_PREFIX}/auth/login")

DbSession = Annotated[Session, Depends(get_db)]

CREDENTIALS_ERROR = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Identifiants invalides ou session expiree",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_current_user(db: DbSession, token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    """Resout l'utilisateur courant a partir du jeton JWT porte par la requete."""
    payload = decode_access_token(token)
    if payload is None or not payload.get("sub"):
        raise CREDENTIALS_ERROR

    user = db.scalar(select(User).where(User.username == payload["sub"]))
    if user is None or not user.is_active:
        raise CREDENTIALS_ERROR
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_roles(*roles: str):
    """Fabrique une dependance qui restreint l'acces aux roles indiques."""

    def guard(user: CurrentUser) -> User:
        """Verifie que l'utilisateur possede l'un des roles autorises."""
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Acces reserve aux roles : {', '.join(roles)}",
            )
        return user

    return guard


AdminUser = Annotated[User, Depends(require_roles(UserRole.ADMIN))]
AnalystUser = Annotated[User, Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))]
