"""Row level security on every table (deny by default)

Supabase publishes the `public` schema through its Data API (PostgREST), reachable with a public key (`anon`).
Without RLS, or with the privileges that Supabase grants by default, anyone holding that key can read and write
these tables (password hashes included) without going through the engine.

What this does, for every table:
- ENABLE ROW LEVEL SECURITY, with no policies: whoever is not the table owner sees no rows.
- REVOKE ALL from `anon` and `authenticated` when those roles exist (only on Supabase).

The engine connects as the table owner (the `postgres` user in Supabase, the database user in docker-compose),
which RLS does not apply to (the tables are not FORCEd), so nothing changes for it. If DATABASE_URL pointed to a
different role without BYPASSRLS, the engine would stop seeing rows after this migration: use the owner.

Revision ID: 006
Revises: 005
Create Date: 2026-10-15
"""
from typing import Sequence, Union

from alembic import op

revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Every table of the application plus Alembic's own. A new migration that creates a table must add it to its own
# ENABLE ROW LEVEL SECURITY: tests/test_rls.py fails if a table in the schema has it off.
TABLES = (
    "users",
    "domains",
    "scan_jobs",
    "subdomains",
    "ports",
    "http_fingerprints",
    "technologies",
    "tls_certificates",
    "findings",
    "audit_log",
    "alembic_version",
)

_TABLE_LIST = ", ".join(f"'{t}'" for t in TABLES)

# Idempotent, and tolerant of a missing table or role. No '%' or ':' in it: psycopg2 and text() read them as parameters.
HARDEN_SQL = f"""
DO $$
DECLARE
  t text;
  r text;
BEGIN
  FOREACH t IN ARRAY ARRAY[{_TABLE_LIST}] LOOP
    IF to_regclass(t) IS NOT NULL THEN
      EXECUTE 'ALTER TABLE ' || quote_ident(t) || ' ENABLE ROW LEVEL SECURITY';
      FOREACH r IN ARRAY ARRAY['anon', 'authenticated'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
          EXECUTE 'REVOKE ALL ON TABLE ' || quote_ident(t) || ' FROM ' || quote_ident(r);
        END IF;
      END LOOP;
    END IF;
  END LOOP;
END $$
"""

RELAX_SQL = f"""
DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[{_TABLE_LIST}] LOOP
    IF to_regclass(t) IS NOT NULL THEN
      EXECUTE 'ALTER TABLE ' || quote_ident(t) || ' DISABLE ROW LEVEL SECURITY';
    END IF;
  END LOOP;
END $$
"""


def upgrade() -> None:
    op.execute(HARDEN_SQL)


def downgrade() -> None:
    # Disables RLS. The privileges revoked from anon/authenticated are not given back: that would re-expose the tables.
    op.execute(RELAX_SQL)
