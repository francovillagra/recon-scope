"""Phase 3: technologies table

Revision ID: 004b
Revises: 004
Create Date: 2026-05-27
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "004b"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "technologies",
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
        sa.Column(
            "http_fingerprint_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("http_fingerprints.id", ondelete="CASCADE"), nullable=True,
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("category", sa.Text(), nullable=True),
        sa.Column("version", sa.Text(), nullable=True),
        sa.Column("confidence", sa.SmallInteger(), nullable=True),
        sa.Column(
            "created_at", sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"), nullable=False,
        ),
        sa.CheckConstraint("confidence BETWEEN 0 AND 100", name="technologies_confidence_check"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_tech_job", "technologies", ["scan_job_id"])
    op.create_index("idx_tech_domain", "technologies", ["domain_id"])


def downgrade() -> None:
    op.drop_index("idx_tech_domain", table_name="technologies")
    op.drop_index("idx_tech_job", table_name="technologies")
    op.drop_table("technologies")
