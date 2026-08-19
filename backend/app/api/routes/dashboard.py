"""Tableau de bord : indicateurs agreges, series temporelles, etat du systeme."""

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import Integer, cast, func, select

from app.api.deps import CurrentUser, DbSession
from app.ml.features import CLASS_NAMES
from app.models import Attack, Flow, Prediction, Statistic
from app.schemas.monitoring import (
    AttackRead,
    ClassConfidence,
    ClassCount,
    DashboardResponse,
    Overview,
    StatisticRead,
    SystemStatus,
    TimeBucket,
)
from app.services.analysis import pipeline

router = APIRouter(tags=["Tableau de bord"])


@router.get("/dashboard", response_model=DashboardResponse, summary="Donnees du tableau de bord")
def dashboard(
    db: DbSession,
    _: CurrentUser,
    hours: Annotated[int, Query(ge=1, le=168)] = 24,
    source: Annotated[str | None, Query(description="simulator | external | tshark")] = None,
) -> DashboardResponse:
    """Agrege toutes les donnees du tableau de bord en une seule reponse.

    `source` restreint l'analyse a une provenance : sans ce filtre, du trafic
    simule et du trafic reel seraient additionnes dans les memes indicateurs.
    """
    since = datetime.now(UTC) - timedelta(hours=hours)

    def par_source(requete, modele):
        """Applique le filtre de provenance si l'appelant en demande un."""
        return requete.where(modele.source == source) if source else requete

    total_flows = db.scalar(par_source(select(func.count(Flow.id)), Flow)) or 0
    requete_attaques = select(func.count(Prediction.id)).where(Prediction.is_attack.is_(True))
    requete_benins = select(func.count(Prediction.id)).where(Prediction.is_attack.is_(False))
    if source:
        # Les predictions n'ont pas de colonne source : on remonte au flux d'origine.
        requete_attaques = requete_attaques.join(Flow).where(Flow.source == source)
        requete_benins = requete_benins.join(Flow).where(Flow.source == source)
    total_attacks = db.scalar(requete_attaques) or 0
    benign_flows = db.scalar(requete_benins) or 0
    active_attacks = (
        db.scalar(par_source(select(func.count(Attack.id)).where(Attack.status == "ACTIVE"), Attack))
        or 0
    )

    last_stat = db.scalar(
        par_source(select(Statistic), Statistic).order_by(Statistic.id.desc()).limit(1)
    )
    last_attack = db.scalar(
        par_source(select(Attack), Attack).order_by(Attack.timestamp.desc()).limit(1)
    )

    distinct_types = (
        db.scalar(select(func.count(func.distinct(Attack.attack_type)))) or 0
    )
    top_source_row = db.execute(
        select(Attack.source_ip, func.count(Attack.id))
        .group_by(Attack.source_ip)
        .order_by(func.count(Attack.id).desc())
        .limit(1)
    ).first()

    classified = total_attacks + benign_flows
    overview = Overview(
        total_flows=total_flows,
        total_attacks=total_attacks,
        benign_flows=benign_flows,
        active_attacks=active_attacks,
        attack_ratio=round(total_attacks / classified * 100, 2) if classified else 0.0,
        packets_per_second=last_stat.packets_per_second if last_stat else 0.0,
        bytes_per_second=last_stat.bytes_per_second if last_stat else 0.0,
        distinct_attack_types=int(distinct_types),
        top_source_ip=top_source_row[0] if top_source_row else None,
        last_attack_at=last_attack.timestamp if last_attack else None,
        system_status="ATTACK" if active_attacks > 0 else "NORMAL",
        updated_at=datetime.now(UTC),
    )

    # ── Histogramme de distribution des classes ───────────────────────────────
    requete_distribution = (
        select(Prediction.prediction, func.count(Prediction.id))
        .where(Prediction.prediction_timestamp >= since)
        .group_by(Prediction.prediction)
    )
    if source:
        requete_distribution = requete_distribution.join(Flow).where(Flow.source == source)
    distribution_rows = dict(db.execute(requete_distribution).all())
    class_distribution = [
        ClassCount(
            name=name,
            count=int(distribution_rows.get(name, 0)),
            is_attack=name != "BENIGN",
        )
        for name in CLASS_NAMES
    ]

    # ── Courbe d'evolution des attaques (agregation horaire) ──────────────────
    bucket = func.date_trunc("hour", Prediction.prediction_timestamp)
    requete_courbe = (
        select(
            bucket.label("bucket"),
            func.sum(cast(Prediction.is_attack, Integer)).label("attacks"),
            func.count(Prediction.id).label("total"),
        )
        .where(Prediction.prediction_timestamp >= since)
        .group_by(bucket)
        .order_by(bucket)
    )
    if source:
        requete_courbe = requete_courbe.join(Flow).where(Flow.source == source)
    time_rows = db.execute(requete_courbe).all()
    attacks_over_time = [
        TimeBucket(
            bucket=row.bucket,
            attacks=int(row.attacks or 0),
            benign=int((row.total or 0) - (row.attacks or 0)),
        )
        for row in time_rows
    ]

    # ── Graphique polaire : confiance moyenne par classe ─────────────────────
    requete_confiance = (
        select(
            Prediction.prediction,
            func.avg(Prediction.confidence),
            func.count(Prediction.id),
        )
        .where(Prediction.prediction_timestamp >= since)
        .group_by(Prediction.prediction)
    )
    if source:
        requete_confiance = requete_confiance.join(Flow).where(Flow.source == source)
    confidence_rows = db.execute(requete_confiance).all()
    confidence_by_class = [
        ClassConfidence(name=name, avg_confidence=round(float(avg or 0), 2), count=int(count))
        for name, avg, count in confidence_rows
    ]

    recent_attacks = list(
        db.execute(
            par_source(select(Attack), Attack).order_by(Attack.timestamp.desc()).limit(10)
        ).scalars()
    )
    throughput_history = list(
        db.execute(
            par_source(select(Statistic), Statistic).order_by(Statistic.id.desc()).limit(60)
        ).scalars()
    )[::-1]

    return DashboardResponse(
        overview=overview,
        class_distribution=class_distribution,
        attacks_over_time=attacks_over_time,
        confidence_by_class=confidence_by_class,
        recent_attacks=[AttackRead.model_validate(a) for a in recent_attacks],
        throughput_history=[StatisticRead.model_validate(s) for s in throughput_history],
    )


@router.get("/stats/live", summary="Statistiques instantanees (page Flux Live)")
def live_stats(
    db: DbSession,
    _: CurrentUser,
    source: Annotated[str | None, Query(description="simulator | external | tshark")] = None,
) -> dict:
    """Statistiques instantanees affichees sur la page Flux Live."""

    def par_source(requete, modele):
        """Applique le filtre de provenance si l'appelant en demande un."""
        return requete.where(modele.source == source) if source else requete

    last_stat = db.scalar(
        par_source(select(Statistic), Statistic).order_by(Statistic.id.desc()).limit(1)
    )
    active_attacks = (
        db.scalar(par_source(select(func.count(Attack.id)).where(Attack.status == "ACTIVE"), Attack))
        or 0
    )
    last_attack = db.scalar(
        par_source(select(Attack), Attack).order_by(Attack.timestamp.desc()).limit(1)
    )

    return {
        "total_flows": last_stat.total_flows if last_stat else 0,
        "total_attacks": last_stat.total_attacks if last_stat else 0,
        "benign_flows": last_stat.benign_flows if last_stat else 0,
        "packets_per_second": last_stat.packets_per_second if last_stat else 0.0,
        "bytes_per_second": last_stat.bytes_per_second if last_stat else 0.0,
        "active_attacks": active_attacks,
        "system_status": "ATTACK" if active_attacks > 0 else "NORMAL",
        "last_attack": AttackRead.model_validate(last_attack).model_dump() if last_attack else None,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@router.get("/stats/history", response_model=list[StatisticRead], summary="Historique du debit")
def stats_history(
    db: DbSession,
    _: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=500)] = 120,
) -> list[Statistic]:
    """Historique du debit reseau, du plus ancien au plus recent."""
    rows = list(db.execute(select(Statistic).order_by(Statistic.id.desc()).limit(limit)).scalars())
    return rows[::-1]


@router.get("/system/status", response_model=SystemStatus, summary="Etat du systeme et du modele")
def system_status(_: CurrentUser) -> dict:
    """Etat du pipeline, de la capture, du modele et du pare-feu."""
    return pipeline.status()
