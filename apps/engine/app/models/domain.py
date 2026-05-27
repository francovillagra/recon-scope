import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import CheckConstraint, ForeignKey, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.scan_job import ScanJob


class Domain(Base):
    """
    Maps to schema.sql §domains.

    BUSINESS RULE: verification_status must equal 'verified' before any
    ScanJob can reference this domain.  Enforced at:
      1. Application layer  — routers/domains.py rejects scan requests.
      2. Database layer     — trigger trg_scan_jobs_domain_verified (migration).
    """

    __tablename__ = "domains"
    __table_args__ = (
        CheckConstraint(
            "verification_status IN ('pending', 'verified', 'failed')",
            name="domains_verification_status_check",
        ),
        CheckConstraint(
            "verification_method IN ('dns_txt', 'well_known_file')",
            name="domains_verification_method_check",
        ),
        UniqueConstraint("user_id", "domain", name="domains_user_domain_key"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    domain: Mapped[str] = mapped_column(nullable=False)
    verification_status: Mapped[str] = mapped_column(
        nullable=False, server_default="pending", index=True
    )
    verification_method: Mapped[str] = mapped_column(
        nullable=False, server_default="dns_txt"
    )
    # Full token value the user must publish, e.g. "recon-verify-<uuid>"
    verification_token: Mapped[str] = mapped_column(nullable=False)
    verified_at: Mapped[Optional[datetime]] = mapped_column(
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
    user: Mapped["User"] = relationship(back_populates="domains")
    scan_jobs: Mapped[list["ScanJob"]] = relationship(
        back_populates="domain", cascade="all, delete-orphan"
    )
