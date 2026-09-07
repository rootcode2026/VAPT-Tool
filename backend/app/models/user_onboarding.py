import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class UserOnboarding(Base):
    __tablename__ = "user_onboarding"
    __table_args__ = (
        UniqueConstraint("user_id", "tour_version", name="uq_user_onboarding_user_version"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    tour_version: Mapped[str] = mapped_column(String(20), nullable=False, default="1", server_default="1")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="not_started", server_default="not_started")
    current_step: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    skipped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), default=datetime.utcnow, onupdate=datetime.utcnow)
