"""Authentification JWT."""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select

from app.api.deps import CurrentUser, DbSession
from app.core.config import settings
from app.core.security import create_access_token, hash_password, verify_password
from app.models import User
from app.schemas.auth import Token, UserRead

router = APIRouter(prefix="/auth", tags=["Authentification"])


@router.post("/login", response_model=Token, summary="Obtenir un jeton d'acces")
def login(db: DbSession, form: Annotated[OAuth2PasswordRequestForm, Depends()]) -> Token:
    """Verifie les identifiants et delivre un jeton JWT."""
    user = db.scalar(select(User).where(User.username == form.username))
    if user is None or not verify_password(form.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nom d'utilisateur ou mot de passe incorrect",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Compte desactive")

    user.last_login = datetime.now(UTC)
    db.commit()

    return Token(
        access_token=create_access_token(subject=user.username, role=user.role),
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserRead.model_validate(user),
    )


@router.get("/me", response_model=UserRead, summary="Profil de l'utilisateur connecte")
def me(user: CurrentUser) -> User:
    """Retourne le profil de l'utilisateur authentifie."""
    return user


@router.post("/change-password", summary="Changer son mot de passe")
def change_password(db: DbSession, user: CurrentUser, current: str, new: str) -> dict[str, str]:
    """Change le mot de passe de l'utilisateur courant."""
    if not verify_password(current, user.password_hash):
        raise HTTPException(status_code=400, detail="Mot de passe actuel incorrect")
    if len(new) < 6:
        raise HTTPException(status_code=400, detail="Le nouveau mot de passe est trop court")
    user.password_hash = hash_password(new)
    db.commit()
    return {"detail": "Mot de passe mis a jour"}
