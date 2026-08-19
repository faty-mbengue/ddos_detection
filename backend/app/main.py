"""Point d'entree de l'API DDoS Monitor."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.api.router import api_router
from app.api.routes import ws
from app.core.config import settings
from app.core.database import SessionLocal, init_db
from app.models import BlockedIP
from app.services import settings_store
from app.services.analysis import pipeline
from app.services.capture import current_backend
from app.services.firewall import firewall
from app.services.ml import load_or_bootstrap

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("ddos-monitor")


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Initialise la base, le modele et le pipeline au demarrage."""
    init_db()

    with SessionLocal() as db:
        from app.scripts.seed import ensure_first_admin

        ensure_first_admin(db)
        settings_store.load_from_db(db)

    load_or_bootstrap()

    # Le pare-feu re-applique la liste persistee : un redemarrage ne doit pas
    # laisser passer des IP deja bloquees.
    firewall.setup()
    if firewall.is_active:
        with SessionLocal() as db:
            adresses = [row.ip_address for row in db.execute(select(BlockedIP)).scalars()]
        logger.info("Pare-feu : %d regle(s) reappliquee(s)", firewall.sync(adresses))

    # En mode "external", aucune boucle locale : l'agent de capture pousse les
    # donnees vers /api/ingest et declenche lui-meme les cycles d'analyse.
    backend_capture = current_backend()
    if settings.CAPTURE_ENABLED and backend_capture != "external":
        await pipeline.start()
    elif backend_capture == "external":
        logger.info("Mode capture externe : en attente de l'agent sur POST /api/ingest")

    logger.info("%s pret (environnement : %s)", settings.PROJECT_NAME, settings.ENVIRONMENT)
    yield

    await pipeline.stop()
    logger.info("Arret propre du systeme")


app = FastAPI(
    title=settings.PROJECT_NAME,
    description=(
        "Plateforme de surveillance et de detection des attaques DDoS en temps reel. "
        "Capture du trafic, classification par Random Forest (CICDDoS2019, 12 classes) "
        "et historisation des alertes."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_V1_PREFIX)
app.include_router(ws.router)


@app.get("/health", tags=["Systeme"], summary="Sonde de sante")
def health() -> dict:
    """Sonde de sante utilisee par Docker et les supervisions externes."""
    from app.services.ml import predictor

    return {
        "status": "ok",
        "project": settings.PROJECT_NAME,
        "model_ready": predictor.is_ready,
        "pipeline_running": pipeline.status()["pipeline_running"],
    }


@app.get("/", tags=["Systeme"], include_in_schema=False)
def root() -> dict:
    """Point d'entree informatif : nom du service et liens utiles."""
    return {
        "name": settings.PROJECT_NAME,
        "version": "1.0.0",
        "docs": "/docs",
        "api": settings.API_V1_PREFIX,
    }
