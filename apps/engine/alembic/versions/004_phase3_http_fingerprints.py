"""Phase 3: http_fingerprints table

Revision ID: 004
Revises: 003
Create Date: 2026-05-27
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "http_fingerprints",
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
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("server_header", sa.Text(), nullable=True),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column(
            "response_headers",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at", sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"), nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_httpfp_job", "http_fingerprints", ["scan_job_id"])
    op.create_index("idx_httpfp_domain", "http_fingerprints", ["domain_id"])


def downgrade() -> None:
    op.drop_index("idx_httpfp_domain", table_name="http_fingerprints")
    op.drop_index("idx_httpfp_job", table_name="http_fingerprints")
    op.drop_table("http_fingerprints")
