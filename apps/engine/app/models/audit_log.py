import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import CheckConstraint, ForeignKey, text, Index
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP, INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.user import User

VALID_ACTIONS = (
    "domain_registered",
    "domain_verified",
    "domain_verification_failed",
    "scan_started",
    "scan_completed",
    "scan_failed",
    "scan_cancelled",
    "report_generated",
)


class AuditLog(Base):
    """
    Maps to schema.sql §audit_log.
    Persists even after users/domains are deleted (user_id SET NULL on delete).
    ip_address uses PostgreSQL's native INET type.
    """

    __tablename__ = "audit_log"
    __table_args__ = (
        CheckConstraint(
            "action IN ("
            + ", ".join(f"'{a}'" for a in VALID_ACTIONS)
            + ")",
            name="audit_log_action_check",
        ),
        Index("idx_audit_user_time", "user_id", "created_at"),
        Index("idx_audit_action", "action"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    action: Mapped[str] = mapped_column(nullable=False)
    target: Mapped[Optional[str]] = mapped_column(nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(INET, nullable=True)
    metadata_: Mapped[dict] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )

    # Relationships
    user: Mapped[Optional["User"]] = relationship(back_populates="audit_logs")
