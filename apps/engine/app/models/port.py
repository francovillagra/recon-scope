import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import CheckConstraint, ForeignKey, Integer, UniqueConstraint, text, Index
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.scan_job import ScanJob
    from app.models.domain import Domain


class Port(Base):
    __tablename__ = "ports"
    __table_args__ = (
        CheckConstraint("port BETWEEN 1 AND 65535", name="ports_port_check"),
        CheckConstraint("protocol IN ('tcp', 'udp')", name="ports_protocol_check"),
        CheckConstraint("state IN ('open', 'closed', 'filtered')", name="ports_state_check"),
        UniqueConstraint(
            "scan_job_id", "host", "port", "protocol",
            name="ports_scan_job_host_port_protocol_key",
        ),
        Index("idx_ports_job", "scan_job_id"),
        Index("idx_ports_domain", "domain_id"),
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
    host: Mapped[str] = mapped_column(nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(nullable=False, server_default="tcp")
    state: Mapped[str] = mapped_column(nullable=False)
    service: Mapped[Optional[str]] = mapped_column(nullable=True)
    banner: Mapped[Optional[str]] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )

    scan_job: Mapped["ScanJob"] = relationship(back_populates="ports")
    domain: Mapped["Domain"] = relationship(back_populates="ports")
