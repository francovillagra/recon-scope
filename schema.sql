-- =====================================================================
-- Automated Reconnaissance Platform — Full Database Schema
-- Target: Supabase (PostgreSQL 15+)
-- Single source of truth for ALL 5 phases. Do not improvise new tables.
--
-- Phase 0: users, domains (ownership verification), audit_log, scan_jobs
-- Phase 1: subdomains
-- Phase 2: ports
-- Phase 3: http_fingerprints, technologies, tls_certificates
-- Phase 4: findings (severity layer) + reports (export)
-- Phase 5: polish (no new tables)
--
-- Conventions:
--   * Primary keys are UUIDs (gen_random_uuid) to avoid ID enumeration.
--   * Enum-like fields use TEXT + CHECK for migration flexibility;
--     validate values app-side with Pydantic (engine) / Zod (web).
--   * All timestamps are timestamptz (never naive).
--   * Authorization is app-level: every query filters by user_id.
--     (See note on RLS at the bottom — depends on your auth choice.)
-- =====================================================================

-- ---------- Extensions ----------
CREATE EXTENSION IF NOT EXISTS pgcrypto; -- provides gen_random_uuid()

-- ---------- Reusable updated_at trigger ----------
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- =====================================================================
-- PHASE 0 — Identity, ownership, audit, job orchestration
-- =====================================================================

-- ---------- users ----------
CREATE TABLE users (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email           TEXT NOT NULL UNIQUE,
  password_hash   TEXT NOT NULL,                 -- bcrypt
  role            TEXT NOT NULL DEFAULT 'user'
                    CHECK (role IN ('user', 'admin')),
  tos_accepted_at TIMESTAMPTZ,                   -- "authorized targets only" acceptance
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER trg_users_updated
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();


-- ---------- domains ----------
-- A user MUST verify ownership before any scan is allowed.
CREATE TABLE domains (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain              TEXT NOT NULL,             -- apex domain, e.g. "example.com"
  verification_status TEXT NOT NULL DEFAULT 'pending'
                        CHECK (verification_status IN ('pending', 'verified', 'failed')),
  verification_method TEXT NOT NULL DEFAULT 'dns_txt'
                        CHECK (verification_method IN ('dns_txt', 'well_known_file')),
  verification_token  TEXT NOT NULL,             -- value the user must publish to prove control
  verified_at         TIMESTAMPTZ,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- same domain can be claimed by different users; each verifies independently
  UNIQUE (user_id, domain)
);

CREATE INDEX idx_domains_user        ON domains (user_id);
CREATE INDEX idx_domains_status      ON domains (verification_status);

CREATE TRIGGER trg_domains_updated
  BEFORE UPDATE ON domains
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();


-- ---------- audit_log ----------
-- Persists even after domains/users are deleted. target is plain text on purpose.
CREATE TABLE audit_log (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
  action      TEXT NOT NULL
                CHECK (action IN (
                  'domain_registered', 'domain_verified', 'domain_verification_failed',
                  'scan_started', 'scan_completed', 'scan_failed', 'scan_cancelled',
                  'report_generated'
                )),
  target      TEXT,                              -- domain / subdomain involved (not an FK)
  ip_address  INET,                              -- requester IP
  metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_user_time ON audit_log (user_id, created_at DESC);
CREATE INDEX idx_audit_action    ON audit_log (action);


-- ---------- scan_jobs ----------
-- One job = one recon run. config jsonb declares which modules run + parameters.
-- Example config:
--   { "modules": ["subdomains","ports","fingerprint"],
--     "port_range": "top-1000", "passive_only": true }
CREATE TABLE scan_jobs (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain_id     UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- denormalized for fast queries
  target        TEXT NOT NULL,                   -- domain or a verified subdomain
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

CREATE INDEX idx_jobs_domain_time ON scan_jobs (domain_id, created_at DESC);
CREATE INDEX idx_jobs_user_status ON scan_jobs (user_id, status);

CREATE TRIGGER trg_jobs_updated
  BEFORE UPDATE ON scan_jobs
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();


-- =====================================================================
-- PHASE 1 — Passive subdomain enumeration (crt.sh, etc.)
-- =====================================================================
CREATE TABLE subdomains (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_job_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  domain_id   UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE, -- cross-job history
  hostname    TEXT NOT NULL,                     -- e.g. "api.example.com"
  source      TEXT NOT NULL
                CHECK (source IN ('crt_sh', 'dns_bruteforce', 'dns_resolution', 'other')),
  resolved_ip INET,                              -- A record at scan time (nullable)
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (scan_job_id, hostname)                 -- one snapshot per job
);

CREATE INDEX idx_subdomains_domain ON subdomains (domain_id);
CREATE INDEX idx_subdomains_job    ON subdomains (scan_job_id);


-- =====================================================================
-- PHASE 2 — Port scanning (asyncio TCP connect scan)
-- =====================================================================
CREATE TABLE ports (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_job_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  domain_id   UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  host        TEXT NOT NULL,                     -- IP or hostname scanned
  port        INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  protocol    TEXT NOT NULL DEFAULT 'tcp'
                CHECK (protocol IN ('tcp', 'udp')),
  state       TEXT NOT NULL
                CHECK (state IN ('open', 'closed', 'filtered')),
  service     TEXT,                              -- inferred service name (nullable)
  banner      TEXT,                              -- banner grab (nullable)
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (scan_job_id, host, port, protocol)
);

CREATE INDEX idx_ports_job        ON ports (scan_job_id);
CREATE INDEX idx_ports_domain     ON ports (domain_id);
CREATE INDEX idx_ports_open       ON ports (scan_job_id) WHERE state = 'open';


-- =====================================================================
-- PHASE 3 — Fingerprinting (HTTP, tech stack, TLS)
-- =====================================================================

-- ---------- http_fingerprints ----------
CREATE TABLE http_fingerprints (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_job_id      UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  domain_id        UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  url              TEXT NOT NULL,                -- URL probed
  status_code      INTEGER,
  server_header    TEXT,
  title            TEXT,                         -- <title> of the page
  response_headers JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_httpfp_job    ON http_fingerprints (scan_job_id);
CREATE INDEX idx_httpfp_domain ON http_fingerprints (domain_id);

-- ---------- technologies ----------
-- Detected tech stack (frameworks, servers, CDNs, analytics...).
CREATE TABLE technologies (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_job_id         UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  domain_id           UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  http_fingerprint_id UUID REFERENCES http_fingerprints(id) ON DELETE CASCADE,
  name                TEXT NOT NULL,             -- e.g. "Next.js", "nginx", "Cloudflare"
  category            TEXT,                      -- e.g. "framework", "web-server", "cdn"
  version             TEXT,
  confidence          SMALLINT CHECK (confidence BETWEEN 0 AND 100),
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_tech_job    ON technologies (scan_job_id);
CREATE INDEX idx_tech_domain ON technologies (domain_id);

-- ---------- tls_certificates ----------
CREATE TABLE tls_certificates (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_job_id         UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  domain_id           UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  host                TEXT NOT NULL,
  issuer              TEXT,
  subject             TEXT,
  valid_from          TIMESTAMPTZ,
  valid_to            TIMESTAMPTZ,
  is_valid            BOOLEAN,                   -- valid + not expired + hostname match
  signature_algorithm TEXT,
  san                 JSONB NOT NULL DEFAULT '[]'::jsonb, -- subject alternative names
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_tls_job    ON tls_certificates (scan_job_id);
CREATE INDEX idx_tls_domain ON tls_certificates (domain_id);


-- =====================================================================
-- PHASE 4 — Findings (severity layer) + report export
-- =====================================================================

-- ---------- findings ----------
-- Interpreted issues derived from raw module data. Powers dashboard + reports.
CREATE TABLE findings (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_job_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  domain_id   UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  category    TEXT NOT NULL
                CHECK (category IN (
                  'exposed_port', 'insecure_tls', 'expired_certificate',
                  'missing_security_header', 'information_disclosure',
                  'outdated_technology', 'subdomain_takeover_risk', 'other'
                )),
  severity    TEXT NOT NULL
                CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  title       TEXT NOT NULL,
  description TEXT,
  evidence    JSONB NOT NULL DEFAULT '{}'::jsonb, -- e.g. { "port": 3306, "host": "..." }
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_findings_job_sev ON findings (scan_job_id, severity);
CREATE INDEX idx_findings_domain  ON findings (domain_id);

-- ---------- reports ----------
CREATE TABLE reports (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_job_id  UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  domain_id    UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  format       TEXT NOT NULL CHECK (format IN ('json', 'pdf')),
  file_url     TEXT,                             -- Supabase Storage URL (nullable if inline)
  generated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_reports_job  ON reports (scan_job_id);
CREATE INDEX idx_reports_user ON reports (user_id);


-- =====================================================================
-- NOTE ON ROW LEVEL SECURITY (decision required)
-- ---------------------------------------------------------------------
-- Supabase recommends RLS. RLS policies based on auth.uid() only work if
-- you use Supabase Auth. Since this project reuses a CUSTOM JWT auth
-- (bcrypt + your own tokens, like Project 1), auth.uid() will be NULL and
-- those policies won't apply.
--
-- Two viable models:
--   (A) App-level authorization (current default): every query filters by
--       user_id. The FastAPI engine uses the service_role key and is the
--       trusted writer; the web app enforces ownership in its own queries.
--   (B) Full RLS: migrate auth to Supabase Auth, then enable RLS and add
--       policies like:
--         ALTER TABLE domains ENABLE ROW LEVEL SECURITY;
--         CREATE POLICY domains_owner ON domains
--           USING (user_id = auth.uid());
--
-- Pick (A) to stay consistent with Project 1, or (B) for defense-in-depth.
-- =====================================================================
