"""Table statistics - metriques globales agregees a chaque cycle d'analyse."""

from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Statistic(Base):
    __tablename__ = "statistics"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )
    total_flows: Mapped[int] = mapped_column(Integer, default=0)
    total_attacks: Mapped[int] = mapped_column(Integer, default=0)
    benign_flows: Mapped[int] = mapped_column(Integer, default=0)
    packets_per_second: Mapped[float] = mapped_column(Float, default=0.0)
    bytes_per_second: Mapped[float] = mapped_column(Float, default=0.0)
    active_attacks: Mapped[int] = mapped_column(Integer, default=0)

    # Provenance de la donnee : "simulator", "external" ou "tshark". Permet de ne
    # jamais melanger du trafic synthetique avec du trafic reel dans les analyses.
    source: Mapped[str] = mapped_column(String(12), default="simulator", index=True)
