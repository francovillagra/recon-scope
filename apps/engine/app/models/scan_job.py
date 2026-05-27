import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import CheckConstraint, ForeignKey, SmallInteger, text, Index
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.domain import Domain


class ScanJob(Base):
    """
    Maps to schema.sql §scan_jobs — Phase 0 stub only.
    Scanning is NOT implemented in Phase 0; this model exists so Alembic can
    create the table and the domain-verified trigger can reference it.

    The DB trigger trg_scan_jobs_domain_verified blocks INSERTs where the
    parent domain is not yet verified.
    """

    __tablename__ = "scan_jobs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled')",
            name="scan_jobs_status_check",
        ),
        CheckConstraint(
            "progress BETWEEN 0 AND 100",
            name="scan_jobs_progress_check",
        ),
        Index("idx_jobs_domain_time", "domain_id", "created_at"),
        Index("idx_jobs_user_status", "user_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    domain_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Denormalised for fast per-user queries (mirrors schema.sql)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    target: Mapped[str] = mapped_column(nullable=False)
    status: Mapped[str] = mapped_column(nullable=False, server_default="queued")
    progress: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default="0"
    )
    config: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    error_message: Mapped[Optional[str]] = mapped_column(nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )

    # Relationships
    user: Mapped["User"] = relationship(back_populates="scan_jobs")
    domain: Mapped["Domain"] = relationship(back_populates="scan_jobs")
