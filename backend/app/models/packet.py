"""Table packets - paquets captures en temps reel (tshark / Wireshark)."""

from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Packet(Base):
    __tablename__ = "packets"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )
    packet_no: Mapped[int] = mapped_column(Integer, default=0)
    time: Mapped[float] = mapped_column(Float, default=0.0)
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), index=True)
    protocol: Mapped[str] = mapped_column(String(10), index=True)
    length: Mapped[int] = mapped_column(Integer, default=0)
    info: Mapped[str] = mapped_column(String(100), default="")

    # Provenance de la donnee : "simulator", "external" ou "tshark". Permet de ne
    # jamais melanger du trafic synthetique avec du trafic reel dans les analyses.
    source: Mapped[str] = mapped_column(String(12), default="simulator", index=True)
