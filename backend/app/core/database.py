"""Connexion PostgreSQL et session SQLAlchemy."""

from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    echo=False,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session]:
    """Dependance FastAPI : une session par requete."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Colonnes ajoutees apres la premiere mise en service. `create_all` ne modifie
# jamais une table existante : sans ce rattrapage, une base deja creee resterait
# sans la colonne et le backend echouerait a l'insertion.
COLONNES_AJOUTEES: tuple[tuple[str, str, str], ...] = (
    ("flows", "source", "VARCHAR(12) NOT NULL DEFAULT 'simulator'"),
    ("packets", "source", "VARCHAR(12) NOT NULL DEFAULT 'simulator'"),
    ("attacks", "source", "VARCHAR(12) NOT NULL DEFAULT 'simulator'"),
    ("statistics", "source", "VARCHAR(12) NOT NULL DEFAULT 'simulator'"),
)


def _appliquer_migrations() -> None:
    """Ajoute les colonnes manquantes, de facon idempotente."""
    with engine.begin() as connexion:
        for table, colonne, definition in COLONNES_AJOUTEES:
            connexion.execute(
                text(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {colonne} {definition}")
            )
            connexion.execute(
                text(f"CREATE INDEX IF NOT EXISTS ix_{table}_{colonne} ON {table} ({colonne})")
            )


def init_db() -> None:
    """Cree les tables au demarrage (les modeles doivent etre importes avant)."""
    from app import models  # noqa: F401  (enregistre les tables sur Base.metadata)

    Base.metadata.create_all(bind=engine)
    _appliquer_migrations()
