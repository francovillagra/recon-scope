-- =============================================================================
-- Migration 0001 — Phase 0: Identity, ownership verification, audit, jobs
-- Target: PostgreSQL 15+ (Supabase or self-hosted)
-- Run once against an empty database.
-- =============================================================================

-- ---------- Extensions -------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto; -- provides gen_random_uuid()

-- ---------- Reusable updated_at trigger --------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- ---------- users ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email           TEXT NOT NULL UNIQUE,
  password_hash   TEXT NOT NULL,
  role            TEXT NOT NULL DEFAULT 'user'
                    CHECK (role IN ('user', 'admin')),
  tos_accepted_at TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER trg_users_updated
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();


-- ---------- domains ----------------------------------------------------------
-- BUSINESS RULE: verification_status MUST be 'verified' before any scan_job
-- can reference this domain. Enforced at application level — see scan_jobs
-- check constraint below.
CREATE TABLE IF NOT EXISTS domains (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain              TEXT NOT NULL,
  verification_status TEXT NOT NULL DEFAULT 'pending'
                        CHECK (verification_status IN ('pending', 'verified', 'failed')),
  verification_method TEXT NOT NULL DEFAULT 'dns_txt'
                        CHECK (verification_method IN ('dns_txt', 'well_known_file')),
  -- The token value the user must publish (full string, e.g. "recon-verify-<uuid>")
  verification_token  TEXT NOT NULL,
  verified_at         TIMESTAMPTZ,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, domain)
);

CREATE INDEX IF NOT EXISTS idx_domains_user   ON domains (user_id);
CREATE INDEX IF NOT EXISTS idx_domains_status ON domains (verification_status);

CREATE TRIGGER trg_domains_updated
  BEFORE UPDATE ON domains
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();


-- ---------- audit_log --------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
  action      TEXT NOT NULL
                CHECK (action IN (
                  'domain_registered', 'domain_verified', 'domain_verification_failed',
                  'scan_started', 'scan_completed', 'scan_failed', 'scan_cancelled',
                  'report_generated'
                )),
  target      TEXT,
  ip_address  INET,
  metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_user_time ON audit_log (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action    ON audit_log (action);


-- ---------- scan_jobs --------------------------------------------------------
-- Placeholder table for Phase 0 — scanning NOT yet implemented.
-- The CHECK constraint enforces the ownership-verification gate at DB level.
CREATE TABLE IF NOT EXISTS scan_jobs (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain_id     UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target        TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'queued'
                  CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
  progress      SMALLINT NOT NULL DEFAULT 0
                  CHECK (progress BETWEEN 0 AND 100),
  config        JSONB NOT NULL DEFAULT '{}'::jsonb,
  error_message TEXT,
  started_at    TIMESTAMPTZ,
  completed_at  TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_jobs_domain_time ON scan_jobs (domain_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_user_status ON scan_jobs (user_id, status);

CREATE TRIGGER trg_jobs_updated
  BEFORE UPDATE ON scan_jobs
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();


-- ---------- DB-level verification gate (enforced via trigger) ----------------
-- Reject any INSERT into scan_jobs if the referenced domain is not verified.
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
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_scan_jobs_domain_verified
  BEFORE INSERT ON scan_jobs
  FOR EACH ROW EXECUTE FUNCTION enforce_domain_verified();
