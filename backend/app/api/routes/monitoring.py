"""Consultation du trafic : paquets temps reel, flux, predictions."""

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Query, Response
from sqlalchemy import func, select
from sqlalchemy.orm import joinedload

from app.api.deps import CurrentUser, DbSession
from app.ml.features import (
    CLASS_NAMES,
    FEATURE_NAMES,
    normalized_vector_from_flow,
    raw_vector_from_flow,
)
from app.models import Flow, Packet, Prediction
from app.schemas.monitoring import (
    FlowSummary,
    PacketRead,
    PredictBatchRequest,
    PredictionDetail,
    PredictRequest,
    PredictResponse,
)
from app.services.ml import predictor

router = APIRouter(tags=["Surveillance"])


# ── Paquets temps reel ────────────────────────────────────────────────────────


@router.get("/packets", response_model=list[PacketRead], summary="Derniers paquets captures")
def list_packets(
    db: DbSession,
    _: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    protocol: str | None = None,
    src_ip: str | None = None,
) -> list[Packet]:
    """Retourne les derniers paquets captures, filtrables par protocole ou source."""
    query = select(Packet).order_by(Packet.id.desc()).limit(limit)
    if protocol:
        query = query.where(Packet.protocol == protocol.upper())
    if src_ip:
        query = query.where(Packet.src_ip == src_ip)
    return list(db.execute(query).scalars())


# ── Flux ──────────────────────────────────────────────────────────────────────


@router.get("/flows", response_model=list[FlowSummary], summary="Flux analyses")
def list_flows(
    db: DbSession,
    _: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    src_ip: str | None = None,
) -> list[Flow]:
    """Retourne les flux analyses, du plus recent au plus ancien."""
    query = select(Flow).order_by(Flow.id.desc()).offset(offset).limit(limit)
    if src_ip:
        query = query.where(Flow.src_ip == src_ip)
    return list(db.execute(query).scalars())


@router.get("/flows/{flow_id}", summary="Detail complet d'un flux (82 colonnes)")
def get_flow(db: DbSession, _: CurrentUser, flow_id: int) -> dict:
    """Detaille un flux : toutes ses colonnes et le vecteur soumis au modele."""
    flow = db.get(Flow, flow_id)
    if flow is None:
        return {"detail": "Flux introuvable"}
    columns = {c.name: getattr(flow, c.name) for c in Flow.__table__.columns}
    return {
        "flow": columns,
        # Les deux vues du vecteur d'entree : brute (ce que recoit le modele) et
        # normalisee (utile pour comparer avec une ligne du notebook).
        "model_input_raw": dict(zip(FEATURE_NAMES, raw_vector_from_flow(flow), strict=True)),
        "model_input_normalized": dict(
            zip(FEATURE_NAMES, normalized_vector_from_flow(flow), strict=True)
        ),
    }


# ── Predictions ───────────────────────────────────────────────────────────────


@router.get(
    "/predictions", response_model=list[PredictionDetail], summary="Resultats de classification"
)
def list_predictions(
    db: DbSession,
    _: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    only_attacks: bool = False,
    attack_type: str | None = None,
    min_confidence: Annotated[float, Query(ge=0, le=100)] = 0,
) -> list[Prediction]:
    """Retourne les classifications, filtrables par classe et par confiance."""
    query = (
        select(Prediction)
        .options(joinedload(Prediction.flow))
        .order_by(Prediction.id.desc())
        .offset(offset)
        .limit(limit)
    )
    if only_attacks:
        query = query.where(Prediction.is_attack.is_(True))
    if attack_type:
        query = query.where(Prediction.prediction == attack_type)
    if min_confidence:
        query = query.where(Prediction.confidence >= min_confidence)
    return list(db.execute(query).unique().scalars())


@router.get("/predictions/distribution", summary="Repartition des classes predites")
def prediction_distribution(
    db: DbSession,
    _: CurrentUser,
    hours: Annotated[int, Query(ge=1, le=720)] = 24,
) -> list[dict]:
    """Compte les predictions par classe sur une fenetre temporelle."""
    since = datetime.now(UTC) - timedelta(hours=hours)
    rows = db.execute(
        select(
            Prediction.prediction,
            func.count(Prediction.id),
            func.avg(Prediction.confidence),
        )
        .where(Prediction.prediction_timestamp >= since)
        .group_by(Prediction.prediction)
    ).all()
    counts = {name: (0, 0.0) for name in CLASS_NAMES}
    for name, count, avg in rows:
        counts[name] = (int(count), float(avg or 0))
    return [
        {
            "name": name,
            "count": count,
            "avg_confidence": round(avg, 2),
            "is_attack": name != "BENIGN",
        }
        for name, (count, avg) in counts.items()
    ]


@router.post("/predict", response_model=PredictResponse, summary="Predire un flux a la demande")
def predict(db: DbSession, _: CurrentUser, payload: PredictRequest) -> PredictResponse:
    """Classe un vecteur fourni par l'appelant et, en option, enregistre le resultat."""
    result = predictor.predict_one(payload.features, already_scaled=payload.scaled)

    if payload.persist:
        db.add(
            Prediction(
                flow_id=None,
                prediction=result.label,
                confidence=result.confidence,
                is_attack=result.is_attack,
            )
        )
        db.commit()

    return PredictResponse(
        prediction=result.label,
        class_index=CLASS_NAMES.index(result.label) if result.label in CLASS_NAMES else -1,
        confidence=result.confidence,
        is_attack=result.is_attack,
        probabilities=result.probabilities,
    )


@router.post("/predict/batch", summary="Predire un lot de flux")
def predict_batch(_: CurrentUser, payload: PredictBatchRequest) -> dict:
    """Classe un lot de vecteurs et resume le nombre d'attaques detectees."""
    results = predictor.predict_batch(payload.rows, already_scaled=payload.scaled)
    return {
        "count": len(results),
        "attacks": sum(1 for r in results if r.is_attack),
        "results": [
            {
                "prediction": r.label,
                "confidence": r.confidence,
                "is_attack": r.is_attack,
            }
            for r in results
        ],
    }


@router.get("/predictions/export", summary="Exporter les predictions en CSV")
def export_predictions(
    db: DbSession,
    _: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=50000)] = 5000,
    only_attacks: bool = False,
) -> Response:
    """Exporte les predictions au format CSV."""
    query = (
        select(Prediction)
        .options(joinedload(Prediction.flow))
        .order_by(Prediction.id.desc())
        .limit(limit)
    )
    if only_attacks:
        query = query.where(Prediction.is_attack.is_(True))

    lines = ["id,timestamp,prediction,confidence,is_attack,src_ip,dst_ip,protocol,flow_bytes_s"]
    for p in db.execute(query).unique().scalars():
        flow = p.flow
        lines.append(
            f"{p.id},{p.prediction_timestamp.isoformat()},{p.prediction},{p.confidence},"
            f"{p.is_attack},{flow.src_ip if flow else ''},{flow.dst_ip if flow else ''},"
            f"{flow.protocol if flow else ''},{flow.flow_byts_s if flow else ''}"
        )

    return Response(
        content="\n".join(lines),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="predictions.csv"'},
    )
