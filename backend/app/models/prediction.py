"""Table predictions - resultats du modele Random Forest."""

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Prediction(Base):
    __tablename__ = "predictions"

    id: Mapped[int] = mapped_column(primary_key=True)
    flow_id: Mapped[int | None] = mapped_column(
        ForeignKey("flows.id", ondelete="CASCADE"), index=True, nullable=True
    )
    prediction: Mapped[str] = mapped_column(String(20), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    is_attack: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    prediction_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )

    flow = relationship("Flow", back_populates="prediction")
