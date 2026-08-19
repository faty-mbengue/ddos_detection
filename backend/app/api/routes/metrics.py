"""Metriques du modele : performances d'entrainement et comportement en production."""

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from app.api.deps import AdminUser, CurrentUser, DbSession
from app.ml.features import CLASS_NAMES, FEATURE_NAMES
from app.models import Prediction
from app.services.ml import load_or_bootstrap, predictor

router = APIRouter(prefix="/model", tags=["Metriques du modele"])


@router.get("/info", summary="Informations sur le modele charge")
def model_info(_: CurrentUser) -> dict:
    """Decrit le modele charge et les artefacts effectivement utilises."""
    return predictor.info()


@router.get("/features", summary="Caracteristiques attendues en entree")
def model_features(_: CurrentUser) -> dict:
    """Retourne les caracteristiques attendues en entree, dans l'ordre exact."""
    return {
        "n_features": len(FEATURE_NAMES),
        "features": FEATURE_NAMES,
        "classes": CLASS_NAMES,
        "note": "Vecteur normalise dans [0, 1], dans cet ordre exact.",
    }


@router.get("/metrics", summary="Performances du modele (entrainement + production)")
def model_metrics(
    db: DbSession,
    _: CurrentUser,
    hours: Annotated[int, Query(ge=1, le=720)] = 24,
) -> dict:
    """Combine les metriques d'entrainement et le comportement observe en production."""
    info = predictor.info()
    training = info.get("metrics") or {}

    since = datetime.now(UTC) - timedelta(hours=hours)
    rows = db.execute(
        select(
            Prediction.prediction,
            func.count(Prediction.id),
            func.avg(Prediction.confidence),
            func.min(Prediction.confidence),
            func.max(Prediction.confidence),
        )
        .where(Prediction.prediction_timestamp >= since)
        .group_by(Prediction.prediction)
    ).all()

    total = sum(int(r[1]) for r in rows)
    production = [
        {
            "class_name": name,
            "count": int(count),
            "share": round(int(count) / total * 100, 2) if total else 0.0,
            "avg_confidence": round(float(avg or 0), 2),
            "min_confidence": round(float(low or 0), 2),
            "max_confidence": round(float(high or 0), 2),
            "is_attack": name != "BENIGN",
            "training": training.get("per_class", {}).get(name),
        }
        for name, count, avg, low, high in rows
    ]
    production.sort(key=lambda row: row["count"], reverse=True)

    detected = sum(row["count"] for row in production if row["is_attack"])

    return {
        "model": {
            "algorithm": info.get("model_type"),
            "dataset": info.get("dataset"),
            "trained_at": info.get("trained_at"),
            "is_demo": info.get("is_demo"),
            "n_features": info.get("n_features"),
            "n_classes": info.get("n_classes"),
        },
        "training": {
            "accuracy": training.get("accuracy"),
            "precision_macro": training.get("precision_macro"),
            "recall_macro": training.get("recall_macro"),
            "f1_macro": training.get("f1_macro"),
            # Moyennes ponderees, lorsque le notebook les fournit
            "precision_weighted": training.get("precision_weighted"),
            "recall_weighted": training.get("recall_weighted"),
            "f1_weighted": training.get("f1_weighted"),
            "per_class": training.get("per_class", {}),
            "confusion_matrix": training.get("confusion_matrix"),
            "labels": info.get("classes", CLASS_NAMES),
            "n_train": training.get("n_train"),
            "n_test": training.get("n_test"),
        },
        # Les importances proviennent du metadata quand il existe, sinon elles sont
        # lues directement dans le modele charge.
        "feature_importances": [
            {"feature": name, "importance": round(value, 5)}
            for name, value in list((training.get("feature_importances") or {}).items())[:15]
        ]
        or predictor.feature_importances(),
        "production": {
            "window_hours": hours,
            "total_predictions": total,
            "attacks_detected": detected,
            "detection_rate": round(detected / total * 100, 2) if total else 0.0,
            "per_class": production,
        },
    }


@router.post("/reload", summary="Recharger le modele depuis le disque (admin)")
def reload_model(_: AdminUser) -> dict:
    """Recharge les artefacts depuis le disque, sans redemarrer le backend."""
    load_or_bootstrap()
    return {"detail": "Modele recharge", "model": predictor.info()}
