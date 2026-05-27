"""
Findings engine — Phase 3.

Queries scan results already committed to the DB and generates Finding rows
according to static rules. Called by scan_runner after all modules complete.
"""
import re
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.http_fingerprint import HttpFingerprint
from app.models.port import Port
from app.models.tls_certificate import TlsCertificate

_VERSION_IN_SERVER_RE = re.compile(r"\d+\.\d+")

# Ports that should raise findings when open
_HIGH_PORTS = {3306, 5432, 27017, 1521, 6379, 5984, 9200}  # DB / data stores
_MEDIUM_PORTS = {22}
_SECURITY_HEADERS = ["content-security-policy", "x-frame-options", "strict-transport-security"]


async def generate_findings(
    job_id: uuid.UUID,
    domain_id: uuid.UUID,
    session: AsyncSession,
) -> list[Finding]:
    findings: list[Finding] = []
    now = datetime.now(timezone.utc)

    # ── load scan data ────────────────────────────────────────────────────────
    open_ports = list(await session.scalars(
        select(Port).where(Port.scan_job_id == job_id, Port.state == "open")
    ))
    tls_certs = list(await session.scalars(
        select(TlsCertificate).where(TlsCertificate.scan_job_id == job_id)
    ))
    fingerprints = list(await session.scalars(
        select(HttpFingerprint).where(HttpFingerprint.scan_job_id == job_id)
    ))

    def add(category: str, severity: str, title: str, description: str, evidence: dict) -> None:
        findings.append(Finding(
            scan_job_id=job_id,
            domain_id=domain_id,
            category=category,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
        ))

    # ── exposed ports ─────────────────────────────────────────────────────────
    for p in open_ports:
        if p.port in _HIGH_PORTS:
            add(
                category="exposed_port",
                severity="high",
                title="Database port exposed",
                description=f"Port {p.port}/{p.protocol} ({p.service or 'unknown'}) is open on {p.host}.",
                evidence={"host": p.host, "port": p.port, "service": p.service},
            )
        elif p.port in _MEDIUM_PORTS:
            add(
                category="exposed_port",
                severity="medium",
                title="SSH exposed",
                description=f"SSH (port {p.port}) is open on {p.host}.",
                evidence={"host": p.host, "port": p.port},
            )

    # ── TLS certificate issues ────────────────────────────────────────────────
    for cert in tls_certs:
        if cert.valid_to and cert.valid_to < now:
            add(
                category="expired_certificate",
                severity="high",
                title="Expired TLS certificate",
                description=f"The TLS certificate for {cert.host} expired on {cert.valid_to.date()}.",
                evidence={"host": cert.host, "valid_to": str(cert.valid_to)},
            )
        elif cert.is_valid is False:
            add(
                category="insecure_tls",
                severity="high",
                title="Invalid or expired TLS certificate",
                description=f"The TLS certificate for {cert.host} failed validation.",
                evidence={"host": cert.host},
            )

    # ── HTTP fingerprint rules ────────────────────────────────────────────────
    for fp in fingerprints:
        headers_lower = {k.lower(): v for k, v in (fp.response_headers or {}).items()}

        # Missing security headers
        for header in _SECURITY_HEADERS:
            if header not in headers_lower:
                add(
                    category="missing_security_header",
                    severity="low",
                    title=f"Missing {header} header",
                    description=f"The response from {fp.url} does not include the '{header}' security header.",
                    evidence={"url": fp.url, "missing_header": header},
                )

        # Server version disclosure
        server = fp.server_header or ""
        if _VERSION_IN_SERVER_RE.search(server):
            add(
                category="information_disclosure",
                severity="low",
                title="Server version disclosure",
                description=f"The Server header '{server}' reveals version information.",
                evidence={"url": fp.url, "server_header": server},
            )

    return findings
