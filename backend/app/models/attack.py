"""Table attacks - alertes consolidees generees a la detection d'une attaque."""

from datetime import UTC, datetime

from sqlalchemy import BigInteger, DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Attack(Base):
    __tablename__ = "attacks"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )
    attack_type: Mapped[str] = mapped_column(String(20), index=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    destination_ip: Mapped[str] = mapped_column(String(45), index=True)
    flows_count: Mapped[int] = mapped_column(Integer, default=0)
    total_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    total_packets: Mapped[int] = mapped_column(BigInteger, default=0)
    duration: Mapped[float] = mapped_column(Float, default=0.0)
    avg_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    # LOW / MEDIUM / HIGH / CRITICAL
    severity: Mapped[str] = mapped_column(String(10), default="MEDIUM", index=True)
    # ACTIVE / MITIGATED
    status: Mapped[str] = mapped_column(String(10), default="ACTIVE", index=True)

    # Provenance de la donnee : "simulator", "external" ou "tshark". Permet de ne
    # jamais melanger du trafic synthetique avec du trafic reel dans les analyses.
    source: Mapped[str] = mapped_column(String(12), default="simulator", index=True)
