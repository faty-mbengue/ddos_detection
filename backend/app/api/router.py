"""Agregation des routes de l'API."""

from fastapi import APIRouter

from app.api.routes import (
    admin,
    analysis,
    attacks,
    auth,
    dashboard,
    ingest,
    metrics,
    monitoring,
)

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(monitoring.router)
api_router.include_router(ingest.router)
api_router.include_router(analysis.router)
api_router.include_router(dashboard.router)
api_router.include_router(attacks.router)
api_router.include_router(metrics.router)
api_router.include_router(admin.router)
