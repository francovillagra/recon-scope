"""Phase 2: ports table (asyncio TCP connect scan)

Revision ID: 003
Revises: 002
Create Date: 2026-05-27
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ports",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "scan_job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "domain_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("domains.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("host", sa.Text(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.Text(), nullable=False, server_default="tcp"),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("service", sa.Text(), nullable=True),
        sa.Column("banner", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("port BETWEEN 1 AND 65535", name="ports_port_check"),
        sa.CheckConstraint("protocol IN ('tcp', 'udp')", name="ports_protocol_check"),
        sa.CheckConstraint(
            "state IN ('open', 'closed', 'filtered')", name="ports_state_check"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scan_job_id", "host", "port", "protocol",
            name="ports_scan_job_host_port_protocol_key",
        ),
    )
    op.create_index("idx_ports_job", "ports", ["scan_job_id"])
    op.create_index("idx_ports_domain", "ports", ["domain_id"])
    # Partial index — only open ports (mirrors schema.sql)
    op.create_index(
        "idx_ports_open",
        "ports",
        ["scan_job_id"],
        postgresql_where=sa.text("state = 'open'"),
    )


def downgrade() -> None:
    op.drop_index("idx_ports_open", table_name="ports")
    op.drop_index("idx_ports_domain", table_name="ports")
    op.drop_index("idx_ports_job", table_name="ports")
    op.drop_table("ports")
