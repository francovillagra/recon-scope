import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import CheckConstraint, ForeignKey, SmallInteger, text, Index
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.scan_job import ScanJob
    from app.models.domain import Domain
    from app.models.http_fingerprint import HttpFingerprint


class Technology(Base):
    __tablename__ = "technologies"
    __table_args__ = (
        CheckConstraint("confidence BETWEEN 0 AND 100", name="technologies_confidence_check"),
        Index("idx_tech_job", "scan_job_id"),
        Index("idx_tech_domain", "domain_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    domain_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("domains.id", ondelete="CASCADE"), nullable=False
    )
    http_fingerprint_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("http_fingerprints.id", ondelete="CASCADE"),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(nullable=False)
    category: Mapped[Optional[str]] = mapped_column(nullable=True)
    version: Mapped[Optional[str]] = mapped_column(nullable=True)
    confidence: Mapped[Optional[int]] = mapped_column(SmallInteger, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )

    scan_job: Mapped["ScanJob"] = relationship(back_populates="technologies")
    domain: Mapped["Domain"] = relationship(back_populates="technologies")
    http_fingerprint: Mapped[Optional["HttpFingerprint"]] = relationship(
        back_populates="technologies"
    )
