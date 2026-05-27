"""Phase 4: findings table (severity layer)

Revision ID: 005
Revises: 004c
Create Date: 2026-05-27
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "005"
down_revision: Union[str, None] = "004c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "findings",
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
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "evidence",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at", sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"), nullable=False,
        ),
        sa.CheckConstraint(
            "category IN ('exposed_port','insecure_tls','expired_certificate',"
            "'missing_security_header','information_disclosure',"
            "'outdated_technology','subdomain_takeover_risk','other')",
            name="findings_category_check",
        ),
        sa.CheckConstraint(
            "severity IN ('info','low','medium','high','critical')",
            name="findings_severity_check",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_findings_job_sev", "findings", ["scan_job_id", "severity"])
    op.create_index("idx_findings_domain", "findings", ["domain_id"])


def downgrade() -> None:
    op.drop_index("idx_findings_domain", table_name="findings")
    op.drop_index("idx_findings_job_sev", table_name="findings")
    op.drop_table("findings")
