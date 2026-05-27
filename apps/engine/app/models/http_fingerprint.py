import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import ForeignKey, Integer, text, Index
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.scan_job import ScanJob
    from app.models.domain import Domain
    from app.models.technology import Technology


class HttpFingerprint(Base):
    __tablename__ = "http_fingerprints"
    __table_args__ = (
        Index("idx_httpfp_job", "scan_job_id"),
        Index("idx_httpfp_domain", "domain_id"),
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
    url: Mapped[str] = mapped_column(nullable=False)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    server_header: Mapped[Optional[str]] = mapped_column(nullable=True)
    title: Mapped[Optional[str]] = mapped_column(nullable=True)
    response_headers: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )

    scan_job: Mapped["ScanJob"] = relationship(back_populates="http_fingerprints")
    domain: Mapped["Domain"] = relationship(back_populates="http_fingerprints")
    technologies: Mapped[list["Technology"]] = relationship(
        back_populates="http_fingerprint", cascade="all, delete-orphan"
    )
