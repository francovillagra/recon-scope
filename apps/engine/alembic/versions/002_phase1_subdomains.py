"""Phase 1: subdomains table (crt.sh passive enumeration)

Revision ID: 002
Revises: 001
Create Date: 2026-05-27

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "subdomains",
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
        sa.Column("hostname", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("resolved_ip", postgresql.INET(), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "source IN ('crt_sh', 'dns_bruteforce', 'dns_resolution', 'other')",
            name="subdomains_source_check",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scan_job_id", "hostname", name="subdomains_scan_job_hostname_key"
        ),
    )
    op.create_index("idx_subdomains_domain", "subdomains", ["domain_id"])
    op.create_index("idx_subdomains_job", "subdomains", ["scan_job_id"])


def downgrade() -> None:
    op.drop_index("idx_subdomains_job", table_name="subdomains")
    op.drop_index("idx_subdomains_domain", table_name="subdomains")
    op.drop_table("subdomains")
