"""Administration : utilisateurs, configuration du systeme, IP bloquees."""

from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, status
from sqlalchemy import select

from app.api.deps import AdminUser, AnalystUser, CurrentUser, DbSession
from app.core.security import hash_password
from app.models import BlockedIP, User
from app.schemas.auth import UserCreate, UserRead, UserUpdate
from app.schemas.monitoring import BlockedIPCreate, BlockedIPRead, SystemSettings
from app.services import settings_store
from app.services.alerts import configuration_status, send_test_email
from app.services.analysis import pipeline
from app.services.capture import CAPTURE_BACKENDS, current_backend
from app.services.firewall import firewall, is_valid_ip
from app.services.interfaces import list_interfaces

router = APIRouter(prefix="/admin", tags=["Administration"])


# ── Utilisateurs ──────────────────────────────────────────────────────────────


@router.get("/users", response_model=list[UserRead], summary="Lister les utilisateurs")
def list_users(db: DbSession, _: AdminUser) -> list[User]:
    """Liste tous les comptes utilisateurs, par identifiant croissant."""
    return list(db.execute(select(User).order_by(User.id)).scalars())


@router.post(
    "/users",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    summary="Creer un utilisateur",
)
def create_user(db: DbSession, _: AdminUser, payload: UserCreate) -> User:
    """Cree un compte apres verification de l'unicite du nom et de l'email."""
    exists = db.scalar(
        select(User).where((User.username == payload.username) | (User.email == payload.email))
    )
    if exists:
        raise HTTPException(status_code=409, detail="Nom d'utilisateur ou email deja utilise")

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.patch("/users/{user_id}", response_model=UserRead, summary="Modifier un utilisateur")
def update_user(db: DbSession, admin: AdminUser, user_id: int, payload: UserUpdate) -> User:
    """Met a jour email, role, activation ou mot de passe d'un compte."""
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    if user.id == admin.id and payload.is_active is False:
        raise HTTPException(status_code=400, detail="Impossible de desactiver son propre compte")

    if payload.email is not None:
        user.email = payload.email
    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
    if payload.password:
        user.password_hash = hash_password(payload.password)

    db.commit()
    db.refresh(user)
    return user


@router.delete("/users/{user_id}", status_code=204, summary="Supprimer un utilisateur")
def delete_user(db: DbSession, admin: AdminUser, user_id: int) -> None:
    """Supprime un compte. Un administrateur ne peut pas supprimer le sien."""
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Impossible de supprimer son propre compte")
    db.delete(user)
    db.commit()


# ── Configuration du systeme ──────────────────────────────────────────────────


@router.get("/settings", summary="Lire la configuration du systeme")
def read_settings(_: CurrentUser) -> dict:
    """Retourne la configuration de detection actuellement appliquee."""
    return settings_store.get_runtime_settings().as_dict()


@router.put("/settings", summary="Mettre a jour la configuration du systeme")
async def write_settings(db: DbSession, _: AdminUser, payload: SystemSettings) -> dict:
    """Applique une mise a jour partielle de la configuration, a chaud.

    Changer `capture_backend` ne suffit pas a modifier le comportement : le
    moteur de capture est instancie une fois puis conserve. On declenche donc
    explicitement la bascule apres l'enregistrement.
    """
    changes = payload.model_dump(exclude_none=True)
    if not changes:
        raise HTTPException(status_code=400, detail="Aucune valeur a mettre a jour")

    nouveau_backend = changes.get("capture_backend")
    if nouveau_backend and nouveau_backend not in CAPTURE_BACKENDS:
        raise HTTPException(
            status_code=422,
            detail=f"Mode de capture inconnu. Valeurs acceptees : {', '.join(CAPTURE_BACKENDS)}",
        )
    bascule = nouveau_backend is not None and nouveau_backend != current_backend()

    resultat = settings_store.update(db, changes).as_dict()
    if bascule:
        await pipeline.switch_backend(str(nouveau_backend))
    return resultat


@router.post("/pipeline/{action}", summary="Demarrer ou arreter la boucle d'analyse")
async def control_pipeline(
    _: AdminUser, action: Annotated[str, Path(pattern="^(start|stop)$")]
) -> dict:
    """Demarre ou arrete la boucle de capture et d'analyse."""
    if action == "start":
        await pipeline.start()
    else:
        await pipeline.stop()
    return pipeline.status()


# ── IP bloquees ───────────────────────────────────────────────────────────────


@router.get("/email", summary="Etat de la configuration des alertes email")
def email_status(_: CurrentUser) -> dict:
    """Indique si les alertes email peuvent partir, et ce qui manque le cas echeant."""
    return configuration_status()


@router.post("/email/test", summary="Envoyer un email de test")
async def email_test(_: AdminUser) -> dict:
    """Envoie un email de test aux destinataires configures et remonte l'erreur eventuelle."""
    return await send_test_email()


@router.get("/interfaces", summary="Interfaces reseau reellement capturables")
def network_interfaces(_: CurrentUser) -> dict:
    """Liste les interfaces observables et explique ce qui serait reellement capture."""
    return list_interfaces()


@router.get("/firewall", summary="Etat du pare-feu (le blocage est-il applique ?)")
def firewall_status(_: CurrentUser) -> dict:
    """Indique si les blocages posent de vraies regles ou restent documentaires."""
    return firewall.status()


@router.get("/blocked-ips", response_model=list[BlockedIPRead], summary="Lister les IP bloquees")
def list_blocked_ips(db: DbSession, _: CurrentUser) -> list[BlockedIP]:
    """Retourne la liste des IP bloquees, de la plus recente a la plus ancienne."""
    return list(db.execute(select(BlockedIP).order_by(BlockedIP.created_at.desc())).scalars())


@router.post(
    "/blocked-ips",
    response_model=BlockedIPRead,
    status_code=status.HTTP_201_CREATED,
    summary="Bloquer une IP",
)
def block_ip(db: DbSession, user: AnalystUser, payload: BlockedIPCreate) -> BlockedIP:
    """Enregistre une IP bloquee et pose la regle de pare-feu si celui-ci est actif."""
    if not is_valid_ip(payload.ip_address):
        raise HTTPException(status_code=422, detail="Adresse IP invalide")

    exists = db.scalar(select(BlockedIP).where(BlockedIP.ip_address == payload.ip_address))
    if exists:
        raise HTTPException(status_code=409, detail="Cette IP est deja bloquee")

    entry = BlockedIP(
        ip_address=payload.ip_address,
        reason=payload.reason,
        blocked_by=user.username,
        is_automatic=False,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    # L'echec du pare-feu n'annule pas l'enregistrement : l'etat reel est
    # consultable via GET /api/admin/firewall et affiche dans l'interface.
    firewall.block(entry.ip_address)
    return entry


@router.delete("/blocked-ips/{blocked_id}", status_code=204, summary="Debloquer une IP")
def unblock_ip(db: DbSession, _: AnalystUser, blocked_id: int) -> None:
    """Retire l'IP de la liste et supprime la regle de pare-feu correspondante."""
    entry = db.get(BlockedIP, blocked_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Entree introuvable")

    firewall.unblock(entry.ip_address)
    db.delete(entry)
    db.commit()
