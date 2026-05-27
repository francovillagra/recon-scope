"""
Maps to schema.sql §subdomains (Phase 1).
UNIQUE (scan_job_id, hostname) — one snapshot per job.
resolved_ip is best-effort: None when the A record didn't resolve at scan time.
"""
import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import CheckConstraint, ForeignKey, UniqueConstraint, text, Index
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP, INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.scan_job import ScanJob
    from app.models.domain import Domain


class Subdomain(Base):
    __tablename__ = "subdomains"
    __table_args__ = (
        CheckConstraint(
            "source IN ('crt_sh', 'dns_bruteforce', 'dns_resolution', 'other')",
            name="subdomains_source_check",
        ),
        UniqueConstraint("scan_job_id", "hostname", name="subdomains_scan_job_hostname_key"),
        Index("idx_subdomains_domain", "domain_id"),
        Index("idx_subdomains_job", "scan_job_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    domain_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
    )
    hostname: Mapped[str] = mapped_column(nullable=False)
    source: Mapped[str] = mapped_column(nullable=False, server_default="crt_sh")
    resolved_ip: Mapped[Optional[str]] = mapped_column(INET, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )

    # Relationships
    scan_job: Mapped["ScanJob"] = relationship(back_populates="subdomains")
    domain: Mapped["Domain"] = relationship(back_populates="subdomains")
