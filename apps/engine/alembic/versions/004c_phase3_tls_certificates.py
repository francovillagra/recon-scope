"""Phase 3: tls_certificates table

Revision ID: 004c
Revises: 004b
Create Date: 2026-05-27
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "004c"
down_revision: Union[str, None] = "004b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "tls_certificates",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"), nullable=False,
        ),
        sa.Column(
            "scan_job_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "domain_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("domains.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("host", sa.Text(), nullable=False),
        sa.Column("issuer", sa.Text(), nullable=True),
        sa.Column("subject", sa.Text(), nullable=True),
        sa.Column("valid_from", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("valid_to", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("is_valid", sa.Boolean(), nullable=True),
        sa.Column("signature_algorithm", sa.Text(), nullable=True),
        sa.Column(
            "san",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "created_at", sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"), nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_tls_job", "tls_certificates", ["scan_job_id"])
    op.create_index("idx_tls_domain", "tls_certificates", ["domain_id"])


def downgrade() -> None:
    op.drop_index("idx_tls_domain", table_name="tls_certificates")
    op.drop_index("idx_tls_job", table_name="tls_certificates")
    op.drop_table("tls_certificates")
