"""Phase 0: users, domains, audit_log, scan_jobs, verification trigger

Revision ID: 001
Revises:
Create Date: 2026-05-27

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ---------- Extensions ---------------------------------------------------
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # ---------- Trigger helper -----------------------------------------------
    op.execute("""
        CREATE OR REPLACE FUNCTION set_updated_at()
        RETURNS TRIGGER AS $$
        BEGIN
          NEW.updated_at = now();
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
    """)

    # ---------- users --------------------------------------------------------
    op.create_table(
        "users",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), server_default="user", nullable=False),
        sa.Column(
            "tos_accepted_at", sa.TIMESTAMP(timezone=True), nullable=True
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("role IN ('user', 'admin')", name="users_role_check"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )
    op.execute("""
        CREATE TRIGGER trg_users_updated
          BEFORE UPDATE ON users
          FOR EACH ROW EXECUTE FUNCTION set_updated_at()
    """)

    # ---------- domains ------------------------------------------------------
    op.create_table(
        "domains",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("domain", sa.Text(), nullable=False),
        sa.Column(
            "verification_status",
            sa.Text(),
            server_default="pending",
            nullable=False,
        ),
        sa.Column(
            "verification_method",
            sa.Text(),
            server_default="dns_txt",
            nullable=False,
        ),
        sa.Column("verification_token", sa.Text(), nullable=False),
        sa.Column(
            "verified_at", sa.TIMESTAMP(timezone=True), nullable=True
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "verification_status IN ('pending', 'verified', 'failed')",
            name="domains_verification_status_check",
        ),
        sa.CheckConstraint(
            "verification_method IN ('dns_txt', 'well_known_file')",
            name="domains_verification_method_check",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "domain", name="domains_user_domain_key"),
    )
    op.create_index("idx_domains_user", "domains", ["user_id"])
    op.create_index("idx_domains_status", "domains", ["verification_status"])
    op.execute("""
        CREATE TRIGGER trg_domains_updated
          BEFORE UPDATE ON domains
          FOR EACH ROW EXECUTE FUNCTION set_updated_at()
    """)

    # ---------- audit_log ----------------------------------------------------
    op.create_table(
        "audit_log",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("target", sa.Text(), nullable=True),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column(
            "metadata",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "action IN ("
            "'domain_registered','domain_verified','domain_verification_failed',"
            "'scan_started','scan_completed','scan_failed','scan_cancelled',"
            "'report_generated'"
            ")",
            name="audit_log_action_check",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_audit_user_time", "audit_log", ["user_id", "created_at"])
    op.create_index("idx_audit_action", "audit_log", ["action"])

    # ---------- scan_jobs (Phase 0 stub) -------------------------------------
    op.create_table(
        "scan_jobs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "domain_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("domains.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default="queued", nullable=False),
        sa.Column(
            "progress", sa.SmallInteger(), server_default="0", nullable=False
        ),
        sa.Column(
            "config",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('queued','running','completed','failed','cancelled')",
            name="scan_jobs_status_check",
        ),
        sa.CheckConstraint(
            "progress BETWEEN 0 AND 100",
            name="scan_jobs_progress_check",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_jobs_domain_time", "scan_jobs", ["domain_id", "created_at"])
    op.create_index("idx_jobs_user_status", "scan_jobs", ["user_id", "status"])
    op.execute("""
        CREATE TRIGGER trg_jobs_updated
          BEFORE UPDATE ON scan_jobs
          FOR EACH ROW EXECUTE FUNCTION set_updated_at()
    """)

    # ---------- DB-level verification gate -----------------------------------
    op.execute("""
        CREATE OR REPLACE FUNCTION enforce_domain_verified()
        RETURNS TRIGGER AS $$
        DECLARE
          v_status TEXT;
        BEGIN
          SELECT verification_status INTO v_status
          FROM domains WHERE id = NEW.domain_id;

          IF v_status IS DISTINCT FROM 'verified' THEN
            RAISE EXCEPTION
              'Domain % is not verified (status: %). Verify ownership before scanning.',
              NEW.domain_id, v_status
              USING ERRCODE = 'P0001';
          END IF;

          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
    """)
    op.execute("""
        CREATE TRIGGER trg_scan_jobs_domain_verified
          BEFORE INSERT ON scan_jobs
          FOR EACH ROW EXECUTE FUNCTION enforce_domain_verified()
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_scan_jobs_domain_verified ON scan_jobs")
    op.execute("DROP FUNCTION IF EXISTS enforce_domain_verified")
    op.drop_table("scan_jobs")
    op.drop_table("audit_log")
    op.execute("DROP TRIGGER IF EXISTS trg_domains_updated ON domains")
    op.drop_table("domains")
    op.execute("DROP TRIGGER IF EXISTS trg_users_updated ON users")
    op.drop_table("users")
    op.execute("DROP FUNCTION IF EXISTS set_updated_at")
