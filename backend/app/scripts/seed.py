"""Initialisation des donnees : compte administrateur et jeu de demonstration."""

from __future__ import annotations

import logging
import random
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal, init_db
from app.core.security import hash_password
from app.ml.features import ATTACK_CLASSES, BENIGN_CLASS
from app.models import Attack, Flow, Prediction, Statistic, User, UserRole
from app.services.capture import LOCAL_TARGETS, random_public_ip, synthesize_flow

logger = logging.getLogger(__name__)


def ensure_first_admin(db: Session) -> User | None:
    """Cree le compte administrateur initial s'il n'existe aucun utilisateur."""
    if db.scalar(select(func.count(User.id))):
        return None

    admin = User(
        username=settings.FIRST_ADMIN_USERNAME,
        email=settings.FIRST_ADMIN_EMAIL,
        password_hash=hash_password(settings.FIRST_ADMIN_PASSWORD),
        role=UserRole.ADMIN,
    )
    analyst = User(
        username="analyst",
        email="analyst@ddos-monitor.local",
        password_hash=hash_password("analyst123"),
        role=UserRole.ANALYST,
    )
    db.add_all([admin, analyst])
    db.commit()
    logger.info("Comptes initiaux crees : %s (admin), analyst", admin.username)
    return admin


def seed_history(db: Session, hours: int = 24, seed: int = 7) -> dict[str, int]:
    """Genere un historique de demonstration pour peupler les graphiques."""
    rng = random.Random(seed)
    now = datetime.now(UTC)
    created = {"flows": 0, "predictions": 0, "attacks": 0, "statistics": 0}

    for hour in range(hours, 0, -1):
        moment = now - timedelta(hours=hour, minutes=rng.randint(0, 59))
        under_attack = rng.random() < 0.35
        attack_class = rng.choice(ATTACK_CLASSES) if under_attack else None
        source_ip = random_public_ip(rng)
        target_ip = rng.choice(LOCAL_TARGETS)

        n_benign = rng.randint(6, 14)
        n_attack = rng.randint(10, 40) if under_attack else 0

        batch: list[tuple[Flow, str, float]] = []
        for _ in range(n_benign):
            payload = synthesize_flow(BENIGN_CLASS, rng, source_ip, target_ip)
            payload["timestamp"] = moment
            batch.append((Flow(**payload), BENIGN_CLASS, rng.uniform(88, 99.9)))
        for _ in range(n_attack):
            payload = synthesize_flow(attack_class or "UDP", rng, source_ip, target_ip)
            payload["timestamp"] = moment
            batch.append((Flow(**payload), attack_class or "UDP", rng.uniform(82, 99.9)))

        db.add_all(flow for flow, _, _ in batch)
        db.flush()

        db.add_all(
            Prediction(
                flow_id=flow.id,
                prediction=label,
                confidence=round(confidence, 2),
                is_attack=label != BENIGN_CLASS,
                prediction_timestamp=moment,
            )
            for flow, label, confidence in batch
        )
        created["flows"] += len(batch)
        created["predictions"] += len(batch)

        if under_attack and n_attack >= 10:
            confidences = [c for _, label, c in batch if label != BENIGN_CLASS]
            avg_confidence = sum(confidences) / len(confidences)
            severity = "CRITICAL" if n_attack >= 35 else "HIGH" if n_attack >= 22 else "MEDIUM"
            db.add(
                Attack(
                    timestamp=moment,
                    attack_type=attack_class or "UDP",
                    source_ip=source_ip,
                    destination_ip=target_ip,
                    flows_count=n_attack,
                    total_bytes=int(sum(f.totlen_fwd_pkts for f, _, _ in batch)),
                    total_packets=int(sum(f.tot_fwd_pkts for f, _, _ in batch)),
                    duration=round(rng.uniform(5, 60), 2),
                    avg_confidence=round(avg_confidence, 2),
                    severity=severity,
                    status="MITIGATED" if hour > 2 else "ACTIVE",
                )
            )
            created["attacks"] += 1

        db.add(
            Statistic(
                timestamp=moment,
                total_flows=created["flows"],
                total_attacks=sum(1 for _, label, _ in batch if label != BENIGN_CLASS),
                benign_flows=n_benign,
                packets_per_second=round(rng.uniform(180, 2400) if under_attack else rng.uniform(30, 160), 2),
                bytes_per_second=round(rng.uniform(2e5, 4e6) if under_attack else rng.uniform(2e4, 2e5), 2),
                active_attacks=1 if under_attack else 0,
            )
        )
        created["statistics"] += 1

    db.commit()
    return created


def main() -> None:
    """Cree les comptes initiaux puis, si la base est vide, un historique de demonstration."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
    init_db()
    with SessionLocal() as db:
        ensure_first_admin(db)
        if db.scalar(select(func.count(Prediction.id))):
            logger.info("Des predictions existent deja — historique de demonstration ignore")
        else:
            result = seed_history(db)
            logger.info(
                "Historique genere : %(flows)s flux, %(predictions)s predictions, "
                "%(attacks)s alertes, %(statistics)s releves",
                result,
            )


if __name__ == "__main__":
    main()
