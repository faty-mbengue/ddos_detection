"""Table blocked_ips - liste des IP bloquees (manuellement ou automatiquement)."""

from datetime import UTC, datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, index=True)
    reason: Mapped[str] = mapped_column(String(200), default="")
    blocked_by: Mapped[str] = mapped_column(String(50), default="system")  # username ou "system"
    is_automatic: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )
