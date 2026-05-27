"""
Scan router — Phase 1 + Phase 2 + Phase 3 + Phase 4 + Phase 5.

POST /scans              — create a scan_job for a verified domain (rate-limited: 10/hour per user).
GET  /scans              — list scan jobs for the authenticated user.
GET  /scans/{job_id}     — job status + all scan data when completed.
GET  /scans/{job_id}/export/json — full ScanDetailResponse as file download.
"""
import time
import uuid
from collections import defaultdict
from datetime import date
from typing import Annotated

import sqlalchemy.exc
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_session
from app.dependencies import get_current_user
from app.models.audit_log import AuditLog
from app.models.domain import Domain
from app.models.finding import Finding
from app.models.http_fingerprint import HttpFingerprint
from app.models.port import Port
from app.models.scan_job import ScanJob
from app.models.subdomain import Subdomain
from app.models.technology import Technology
from app.models.tls_certificate import TlsCertificate
from app.models.user import User
from app.schemas.scan import (
    CreateScanRequest,
    CreateScanResponse,
    FindingOut,
    HttpFingerprintOut,
    PortOut,
    ScanDetailResponse,
    ScanJobOut,
    SubdomainOut,
    TechnologyOut,
    TlsCertificateOut,
)
from app.services.scan_runner import run_scan

router = APIRouter(prefix="/scans", tags=["scans"])

AuthDep = Annotated[User, Depends(get_current_user)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]

# ── In-memory rate limiter ────────────────────────────────────────────────────

_RATE_LIMIT = 10
_RATE_WINDOW = 3600  # seconds
_scan_timestamps: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(user_id: str) -> None:
    now = time.time()
    cutoff = now - _RATE_WINDOW
    _scan_timestamps[user_id] = [t for t in _scan_timestamps[user_id] if t > cutoff]
    if len(_scan_timestamps[user_id]) >= _RATE_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {_RATE_LIMIT} scans per hour per user.",
        )
    _scan_timestamps[user_id].append(now)


# ── shared helper ─────────────────────────────────────────────────────────────

async def _load_scan_detail(
    job_id: uuid.UUID,
    current_user: User,
    session: AsyncSession,
) -> ScanDetailResponse:
    job = await session.get(ScanJob, job_id)
    if job is None or job.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    subs: list[SubdomainOut] = []
    ports: list[PortOut] = []
    fingerprints: list[HttpFingerprintOut] = []
    technologies: list[TechnologyOut] = []
    tls_certs: list[TlsCertificateOut] = []
    findings: list[FindingOut] = []

    if job.status == "completed":
        sub_rows = await session.scalars(
            select(Subdomain).where(Subdomain.scan_job_id == job_id).order_by(Subdomain.hostname)
        )
        subs = [SubdomainOut.model_validate(s) for s in sub_rows]

        port_rows = await session.scalars(
            select(Port)
            .where(Port.scan_job_id == job_id, Port.state == "open")
            .order_by(Port.host, Port.port)
        )
        ports = [PortOut.model_validate(p) for p in port_rows]

        fp_rows = await session.scalars(
            select(HttpFingerprint)
            .where(HttpFingerprint.scan_job_id == job_id)
            .order_by(HttpFingerprint.url)
        )
        fingerprints = [HttpFingerprintOut.model_validate(f) for f in fp_rows]

        tech_rows = await session.scalars(
            select(Technology).where(Technology.scan_job_id == job_id).order_by(Technology.name)
        )
        technologies = [TechnologyOut.model_validate(t) for t in tech_rows]

        tls_rows = await session.scalars(
            select(TlsCertificate)
            .where(TlsCertificate.scan_job_id == job_id)
            .order_by(TlsCertificate.host)
        )
        tls_certs = [TlsCertificateOut.model_validate(c) for c in tls_rows]

        finding_rows = await session.scalars(
            select(Finding)
            .where(Finding.scan_job_id == job_id)
            .order_by(Finding.severity, Finding.category)
        )
        findings = [FindingOut.model_validate(f) for f in finding_rows]

    return ScanDetailResponse(
        job=ScanJobOut.model_validate(job),
        subdomains=subs,
        ports=ports,
        http_fingerprints=fingerprints,
        technologies=technologies,
        tls_certificates=tls_certs,
        findings=findings,
    )


# ── POST /scans ───────────────────────────────────────────────────────────────

@router.post("", response_model=CreateScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    body: CreateScanRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: AuthDep,
    session: SessionDep,
) -> CreateScanResponse:
    _check_rate_limit(str(current_user.id))

    domain = await session.get(Domain, body.domain_id)
    if domain is None or domain.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found")

    if domain.verification_status != "verified":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Domain not verified. Verify ownership before scanning.",
        )

    config = {
        "modules": body.modules,
        "port_range": body.port_range,
        "passive_only": body.passive_only,
        "timeout_seconds": body.timeout_seconds,
    }
    job = ScanJob(
        domain_id=domain.id,
        user_id=current_user.id,
        target=domain.domain,
        config=config,
    )
    session.add(job)
    session.add(AuditLog(
        user_id=current_user.id,
        action="scan_started",
        target=domain.domain,
        ip_address=request.client.host if request.client else None,
        metadata_={"modules": body.modules},
    ))

    try:
        await session.flush()
        await session.commit()
        await session.refresh(job)
    except sqlalchemy.exc.DBAPIError as e:
        if getattr(e.orig, "pgcode", None) == "P0001":
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Domain not verified. Verify ownership before scanning.",
            )
        raise

    background_tasks.add_task(run_scan, job.id)
    return CreateScanResponse(job_id=job.id, status="queued")


# ── GET /scans ────────────────────────────────────────────────────────────────

@router.get("", response_model=list[ScanJobOut])
async def list_scans(current_user: AuthDep, session: SessionDep) -> list[ScanJobOut]:
    rows = await session.scalars(
        select(ScanJob)
        .where(ScanJob.user_id == current_user.id)
        .order_by(ScanJob.created_at.desc())
    )
    return [ScanJobOut.model_validate(j) for j in rows]


# ── GET /scans/{job_id} ───────────────────────────────────────────────────────

@router.get("/{job_id}", response_model=ScanDetailResponse)
async def get_scan(
    job_id: uuid.UUID,
    current_user: AuthDep,
    session: SessionDep,
) -> ScanDetailResponse:
    return await _load_scan_detail(job_id, current_user, session)


# ── GET /scans/{job_id}/export/json ──────────────────────────────────────────

@router.get("/{job_id}/export/json")
async def export_scan_json(
    job_id: uuid.UUID,
    current_user: AuthDep,
    session: SessionDep,
) -> Response:
    detail = await _load_scan_detail(job_id, current_user, session)
    json_bytes = detail.model_dump_json(indent=2).encode("utf-8")
    domain_slug = detail.job.target.replace(".", "-")
    filename = f"recon-scope-{domain_slug}-{date.today().isoformat()}.json"
    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
