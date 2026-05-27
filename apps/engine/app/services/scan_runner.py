"""
Background job runner for Phase 1 scans.

Each public function creates its own DB sessions so it is safe to run
as a FastAPI BackgroundTask (outside the request's session scope).

Progress checkpoints:
  5%  → running (fetching from crt.sh)
  60% → crt.sh payload received, starting DNS resolution
  90% → DNS done, persisting subdomains
  100% → completed
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from app.database import AsyncSessionLocal
from app.models.audit_log import AuditLog
from app.models.scan_job import ScanJob
from app.models.subdomain import Subdomain
from app.recon.subdomains import SubdomainResult, enumerate_subdomains

logger = logging.getLogger(__name__)


async def _set_progress(job_id: uuid.UUID, progress: int) -> None:
    async with AsyncSessionLocal() as s:
        job = await s.get(ScanJob, job_id)
        if job:
            job.progress = progress
            await s.commit()


async def run_scan(job_id: uuid.UUID) -> None:
    """
    Dispatched by FastAPI BackgroundTasks immediately after the scan_job INSERT.
    Executes all modules listed in job.config["modules"].
    Currently only "subdomains" (crt.sh + DNS resolution) is implemented.
    """
    # ── 1. Mark running ───────────────────────────────────────────────────────
    async with AsyncSessionLocal() as s:
        job = await s.get(ScanJob, job_id)
        if not job:
            logger.error("run_scan: job %s not found", job_id)
            return

        domain_name: str = job.target
        domain_id: uuid.UUID = job.domain_id
        user_id: uuid.UUID = job.user_id
        modules: list[str] = job.config.get("modules", ["subdomains"])

        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        job.progress = 5
        await s.commit()

    logger.info("Scan %s started for %s (modules=%s)", job_id, domain_name, modules)

    # ── 2. Execute modules ────────────────────────────────────────────────────
    results: list[SubdomainResult] = []
    error: Optional[Exception] = None

    if "subdomains" in modules:
        try:
            results = await enumerate_subdomains(domain_name)
            await _set_progress(job_id, 60)

            # DNS resolution is embedded in enumerate_subdomains; by the time
            # we're here all A-record lookups are complete.
            await _set_progress(job_id, 90)
        except Exception as exc:
            logger.exception("Scan %s failed during subdomain enumeration", job_id)
            error = exc

    # ── 3. Persist results ────────────────────────────────────────────────────
    async with AsyncSessionLocal() as s:
        job = await s.get(ScanJob, job_id)
        if not job:
            return

        if error:
            job.status = "failed"
            job.error_message = str(error)[:500]
            job.completed_at = datetime.now(timezone.utc)
            s.add(AuditLog(
                user_id=user_id,
                action="scan_failed",
                target=domain_name,
                metadata_={
                    "job_id": str(job_id),
                    "error": str(error)[:200],
                },
            ))
            logger.warning("Scan %s failed: %s", job_id, error)
        else:
            for r in results:
                s.add(Subdomain(
                    scan_job_id=job_id,
                    domain_id=domain_id,
                    hostname=r.hostname,
                    source=r.source,
                    resolved_ip=r.resolved_ip,
                ))
            job.status = "completed"
            job.progress = 100
            job.completed_at = datetime.now(timezone.utc)
            s.add(AuditLog(
                user_id=user_id,
                action="scan_completed",
                target=domain_name,
                metadata_={
                    "job_id": str(job_id),
                    "subdomains_found": len(results),
                },
            ))
            logger.info(
                "Scan %s completed: %d subdomains found for %s",
                job_id, len(results), domain_name,
            )

        await s.commit()
