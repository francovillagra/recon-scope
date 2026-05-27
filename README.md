# Recon Platform

> **Authorized targets only.**
> This platform is designed exclusively for security testing against targets you **own** or have **explicit written permission** to test. Unauthorized scanning is illegal in most jurisdictions. By registering and using this platform you agree that you are solely responsible for ensuring you have the necessary authorization for every target you add.

---

## Architecture

```mermaid
graph TB
    subgraph "Browser"
        WEB["Next.js 14\n(Dashboard)"]
    end

    subgraph "apps/api  :3001"
        API["Fastify REST\n/api/v1/*"]
        AUTH["Auth\n/auth/register\n/auth/login"]
        DOMAINS["Domains\n/domains/**"]
        VFY["VerificationService\nDNS TXT · .well-known"]
    end

    subgraph "packages"
        CORE["@recon/core\n(shared types)"]
        DB["@recon/db\n(pg pool · migrations)"]
    end

    subgraph "PostgreSQL (Supabase / Docker)"
        PG[("postgres")]
        T_USERS[["users"]]
        T_DOMAINS[["domains"]]
        T_AUDIT[["audit_log"]]
        T_JOBS[["scan_jobs\n(Phase 0 stub)"]]
    end

    WEB -->|"JWT Bearer"| API
    API --> AUTH
    API --> DOMAINS
    DOMAINS --> VFY
    VFY -->|"dns.resolveTxt"| DNS[["Public DNS"]]
    VFY -->|"fetch /.well-known"| INTERNET[["Target server"]]
    AUTH --> DB
    DOMAINS --> DB
    DB --> PG
    PG --> T_USERS & T_DOMAINS & T_AUDIT & T_JOBS
    API -.->|"types"| CORE
    DB -.->|"types"| CORE

    style WEB fill:#0284c7,color:#fff
    style API fill:#0369a1,color:#fff
    style PG fill:#334155,color:#fff
```

### Ownership verification gate

```mermaid
sequenceDiagram
    actor User
    participant Web
    participant API
    participant DNS/File as DNS / .well-known

    User->>Web: Enter domain name
    Web->>API: POST /api/v1/domains
    API-->>Web: { domain, instructions: { dns_txt, well_known_file } }
    Web-->>User: Show verification instructions

    Note over User,DNS/File: User publishes DNS TXT record OR uploads file

    User->>Web: Click "Check"
    Web->>API: POST /api/v1/domains/:id/verify { method }
    API->>DNS/File: Resolve TXT / fetch file
    DNS/File-->>API: Record/file content
    alt Token matches
        API-->>Web: { domain: { verification_status: "verified" } }
        Web-->>User: ✓ Verified — ready to scan
    else Token missing / mismatch
        API-->>Web: 422 + instructions to retry
        Web-->>User: Verification failed — try again
    end
```

---

## Project structure

```
recon-platform/
├── apps/
│   ├── api/          # Fastify REST API  (port 3001)
│   └── web/          # Next.js dashboard (port 3000)
├── packages/
│   ├── core/         # Shared TypeScript types
│   └── db/           # pg pool client + migrations
├── infra/
│   └── docker-compose.yml
├── .env.example
└── schema.sql        # Canonical full-schema reference (all 5 phases)
```

---

## Phases

| Phase | Scope | Status |
|-------|-------|--------|
| **0** | Auth, domain registration, ownership verification, audit log | **✅ Implemented** |
| 1 | Passive subdomain enumeration (crt.sh, DNS brute-force) | 🔜 |
| 2 | Port scanning (async TCP connect) | 🔜 |
| 3 | HTTP fingerprinting, TLS certificates, tech detection | 🔜 |
| 4 | Findings (severity layer), PDF/JSON report export | 🔜 |
| 5 | Polish — no new tables | 🔜 |

---

## Quick start

### Prerequisites

- [pnpm](https://pnpm.io/) ≥ 9
- Node 20+
- Docker + Docker Compose (for local Postgres)

### 1. Install dependencies

```bash
pnpm install
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env — set DATABASE_URL and JWT_SECRET at minimum
```

### 3a. Local development (Postgres via Docker)

```bash
# Start Postgres
docker compose -f infra/docker-compose.yml up postgres -d

# Run Phase 0 migration
DATABASE_URL=postgresql://recon:recon@localhost:5432/recon \
  node packages/db/scripts/migrate.js

# Start API + Web in watch mode
pnpm dev
```

### 3b. Full Docker Compose

```bash
docker compose -f infra/docker-compose.yml up --build
```

- Web: http://localhost:3000
- API: http://localhost:3001
- Health: http://localhost:3001/api/v1/health

### 4. Using Supabase

Set `DATABASE_URL` to your Supabase **Session pooler** connection string, then run the migration:

```bash
node packages/db/scripts/migrate.js
```

---

## API reference (Phase 0)

All endpoints are prefixed with `/api/v1`.

### Auth

| Method | Path | Body | Auth |
|--------|------|------|------|
| `POST` | `/auth/register` | `{ email, password, tos_accepted: true }` | — |
| `POST` | `/auth/login` | `{ email, password }` | — |

Both return `{ token, user }`. Pass `token` as `Authorization: Bearer <token>`.

### Domains

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/domains` | List user's domains |
| `POST` | `/domains` | Register a domain (generates verification token) |
| `GET` | `/domains/:id` | Get domain + verification instructions |
| `POST` | `/domains/:id/verify` | Trigger ownership check |
| `DELETE` | `/domains/:id` | Remove domain |

`POST /domains/:id/verify` body: `{ method: "dns_txt" | "well_known_file" }` (default: `dns_txt`)

#### DNS TXT method

Add a `TXT` record to your domain's DNS:

| Field | Value |
|-------|-------|
| Name | `_recon-verify.<yourdomain>` |
| Type | `TXT` |
| Value | `recon-verify-<uuid>` (returned by the API) |

#### File method

Host a plain-text file:

```
https://<yourdomain>/.well-known/recon-verification.txt
```

Contents: the token string (`recon-verify-<uuid>`).

---

## Security design notes

- **Verification gate enforced at two layers**: application logic in `POST /domains/:id/verify` (returns 422 if not verified) and a PostgreSQL trigger `trg_scan_jobs_domain_verified` that raises an exception if a `scan_jobs` INSERT references an unverified domain.
- **Custom JWT auth** — bcrypt (rounds: 12), HS256 tokens, 7-day expiry. Consistent with the existing auth pattern from Project 1.
- `tos_accepted_at` is set server-side on register. Client must send `tos_accepted: true`; registration is rejected otherwise.
- All audit events (register, verify, verify-failed) are written to `audit_log` with requester IP.
- Passwords are never returned by any endpoint. Login uses a dummy hash for constant-time comparison when the email does not exist.

---

## Development

```bash
pnpm build        # build all packages + apps
pnpm type-check   # TypeScript across the monorepo
pnpm lint         # ESLint
```
