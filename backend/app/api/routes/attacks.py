"""Historique des alertes : consultation, filtrage, export, mitigation."""

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Response
from sqlalchemy import func, or_, select

from app.api.deps import AnalystUser, CurrentUser, DbSession
from app.models import Attack
from app.schemas.monitoring import AttackRead

router = APIRouter(prefix="/attacks", tags=["Historique des alertes"])

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _filtered_query(
    attack_type: str | None,
    severity: str | None,
    attack_status: str | None,
    ip: str | None,
    since: datetime | None,
    until: datetime | None,
):
    """Construit la requete d'alertes correspondant aux filtres fournis."""
    query = select(Attack)
    if attack_type:
        query = query.where(Attack.attack_type == attack_type)
    if severity:
        query = query.where(Attack.severity == severity.upper())
    if attack_status:
        query = query.where(Attack.status == attack_status.upper())
    if ip:
        query = query.where(or_(Attack.source_ip.contains(ip), Attack.destination_ip.contains(ip)))
    if since:
        query = query.where(Attack.timestamp >= since)
    if until:
        query = query.where(Attack.timestamp <= until)
    return query


@router.get("", summary="Journal des alertes (filtrable et pagine)")
def list_attacks(
    db: DbSession,
    _: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    attack_type: str | None = None,
    severity: str | None = None,
    attack_status: str | None = None,
    ip: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    sort: Annotated[str, Query(pattern="^(recent|severity)$")] = "recent",
) -> dict:
    """Retourne le journal des alertes, filtre, trie et pagine."""
    base = _filtered_query(attack_type, severity, attack_status, ip, since, until)

    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    rows = list(db.execute(base.order_by(Attack.timestamp.desc()).limit(2000)).scalars())

    if sort == "severity":
        rows.sort(key=lambda a: (SEVERITY_ORDER.get(a.severity, 9), -a.timestamp.timestamp()))

    page = rows[offset : offset + limit]
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [AttackRead.model_validate(a).model_dump() for a in page],
    }


@router.get("/types", summary="Types d'attaques presents dans l'historique")
def attack_types(db: DbSession, _: CurrentUser) -> list[dict]:
    """Liste les types d'attaques presents dans l'historique, avec leur volume."""
    rows = db.execute(
        select(Attack.attack_type, func.count(Attack.id))
        .group_by(Attack.attack_type)
        .order_by(func.count(Attack.id).desc())
    ).all()
    return [{"attack_type": name, "count": int(count)} for name, count in rows]


@router.get("/summary", summary="Synthese par criticite et par type")
def attack_summary(
    db: DbSession,
    _: CurrentUser,
    hours: Annotated[int, Query(ge=1, le=720)] = 24,
) -> dict:
    """Synthese des alertes sur une fenetre : par criticite, par type, top sources."""
    since = datetime.now(UTC) - timedelta(hours=hours)
    by_severity = db.execute(
        select(Attack.severity, func.count(Attack.id))
        .where(Attack.timestamp >= since)
        .group_by(Attack.severity)
    ).all()
    by_type = db.execute(
        select(Attack.attack_type, func.count(Attack.id), func.avg(Attack.avg_confidence))
        .where(Attack.timestamp >= since)
        .group_by(Attack.attack_type)
        .order_by(func.count(Attack.id).desc())
    ).all()
    top_sources = db.execute(
        select(Attack.source_ip, func.count(Attack.id), func.sum(Attack.flows_count))
        .where(Attack.timestamp >= since)
        .group_by(Attack.source_ip)
        .order_by(func.count(Attack.id).desc())
        .limit(10)
    ).all()

    return {
        "window_hours": hours,
        "by_severity": [{"severity": s, "count": int(c)} for s, c in by_severity],
        "by_type": [
            {"attack_type": t, "count": int(c), "avg_confidence": round(float(a or 0), 2)}
            for t, c, a in by_type
        ],
        "top_sources": [
            {"source_ip": ip, "alerts": int(c), "flows": int(f or 0)} for ip, c, f in top_sources
        ],
    }


@router.get("/{attack_id}", response_model=AttackRead, summary="Detail d'une alerte")
def get_attack(db: DbSession, _: CurrentUser, attack_id: int) -> Attack:
    """Retourne le detail d'une alerte."""
    attack = db.get(Attack, attack_id)
    if attack is None:
        raise HTTPException(status_code=404, detail="Alerte introuvable")
    return attack


@router.patch("/{attack_id}/mitigate", response_model=AttackRead, summary="Marquer comme mitigee")
def mitigate(db: DbSession, _: AnalystUser, attack_id: int) -> Attack:
    """Marque une alerte comme traitee (statut MITIGATED)."""
    attack = db.get(Attack, attack_id)
    if attack is None:
        raise HTTPException(status_code=404, detail="Alerte introuvable")
    attack.status = "MITIGATED"
    db.commit()
    db.refresh(attack)
    return attack


@router.get("/export/csv", summary="Exporter l'historique en CSV")
def export_attacks(
    db: DbSession,
    _: CurrentUser,
    attack_type: str | None = None,
    severity: str | None = None,
    ip: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> Response:
    """Exporte l'historique filtre au format CSV."""
    query = _filtered_query(attack_type, severity, None, ip, since, until)
    rows = db.execute(query.order_by(Attack.timestamp.desc()).limit(50000)).scalars()

    lines = [
        "id,timestamp,attack_type,source_ip,destination_ip,flows_count,"
        "total_packets,total_bytes,duration,avg_confidence,severity,status"
    ]
    for a in rows:
        lines.append(
            f"{a.id},{a.timestamp.isoformat()},{a.attack_type},{a.source_ip},{a.destination_ip},"
            f"{a.flows_count},{a.total_packets},{a.total_bytes},{a.duration},"
            f"{a.avg_confidence},{a.severity},{a.status}"
        )

    return Response(
        content="\n".join(lines),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="historique_alertes.csv"'},
    )
