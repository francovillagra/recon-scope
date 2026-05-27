"""
Scan router — Phase 1 + Phase 2.

POST /scans   — create a scan_job for a verified domain, enqueue background task.
GET  /scans   — list scan jobs for the authenticated user.
GET  /scans/{job_id} — job status + subdomains + open ports when completed.

The DB trigger enforce_domain_verified (migration 001) is the last-resort gate;
the application layer checks verification_status first and returns a clean 422.
"""
import uuid
from typing import Annotated

import sqlalchemy.exc
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_session
from app.dependencies import get_current_user
from app.models.audit_log import AuditLog
from app.models.domain import Domain
from app.models.port import Port
from app.models.scan_job import ScanJob
from app.models.subdomain import Subdomain
from app.models.user import User
from app.schemas.scan import (
    CreateScanRequest,
    CreateScanResponse,
    PortOut,
    ScanDetailResponse,
    ScanJobOut,
    SubdomainOut,
)
from app.services.scan_runner import run_scan

router = APIRouter(prefix="/scans", tags=["scans"])

AuthDep = Annotated[User, Depends(get_current_user)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]


# ── POST /scans ───────────────────────────────────────────────────────────────

@router.post("", response_model=CreateScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    body: CreateScanRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: AuthDep,
    session: SessionDep,
) -> CreateScanResponse:
    # Validate domain ownership
    domain = await session.get(Domain, body.domain_id)
    if domain is None or domain.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found")

    # Application-level gate: must be verified before scanning
    if domain.verification_status != "verified":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Domain not verified. Verify ownership before scanning.",
        )

    # Build the canonical config shape
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
        # DB-level safety net: enforce_domain_verified trigger (pgcode P0001)
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
async def list_scans(
    current_user: AuthDep,
    session: SessionDep,
) -> list[ScanJobOut]:
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
    job = await session.get(ScanJob, job_id)
    if job is None or job.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    subs: list[SubdomainOut] = []
    ports: list[PortOut] = []

    if job.status == "completed":
        sub_rows = await session.scalars(
            select(Subdomain)
            .where(Subdomain.scan_job_id == job_id)
            .order_by(Subdomain.hostname)
        )
        subs = [SubdomainOut.model_validate(s) for s in sub_rows]

        port_rows = await session.scalars(
            select(Port)
            .where(Port.scan_job_id == job_id, Port.state == "open")
            .order_by(Port.host, Port.port)
        )
        ports = [PortOut.model_validate(p) for p in port_rows]

    return ScanDetailResponse(
        job=ScanJobOut.model_validate(job),
        subdomains=subs,
        ports=ports,
    )
