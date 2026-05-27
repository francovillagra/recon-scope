import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, text, Index
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.scan_job import ScanJob
    from app.models.domain import Domain


class TlsCertificate(Base):
    __tablename__ = "tls_certificates"
    __table_args__ = (
        Index("idx_tls_job", "scan_job_id"),
        Index("idx_tls_domain", "domain_id"),
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
    host: Mapped[str] = mapped_column(nullable=False)
    issuer: Mapped[Optional[str]] = mapped_column(nullable=True)
    subject: Mapped[Optional[str]] = mapped_column(nullable=True)
    valid_from: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    valid_to: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    is_valid: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    signature_algorithm: Mapped[Optional[str]] = mapped_column(nullable=True)
    san: Mapped[list] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )

    scan_job: Mapped["ScanJob"] = relationship(back_populates="tls_certificates")
    domain: Mapped["Domain"] = relationship(back_populates="tls_certificates")
