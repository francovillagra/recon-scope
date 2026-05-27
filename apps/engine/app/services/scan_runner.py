"""
Background job runner for Phase 1 + Phase 2 scans.

Each public function creates its own DB sessions so it is safe to run
as a FastAPI BackgroundTask (outside the request's session scope).

Progress checkpoints by active module set:
  subdomains only:      5 → 60 → 90 → 100
  ports only:           5 → 40 → 90 → 100
  subdomains + ports:   5 → 30 → 60 → 80 → 100
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from app.database import AsyncSessionLocal
from app.models.audit_log import AuditLog
from app.models.port import Port
from app.models.scan_job import ScanJob
from app.models.subdomain import Subdomain
from app.recon.ports import PortResult, scan_ports
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
    Executes modules listed in job.config["modules"].
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
        cfg: dict = job.config
        modules: list[str] = cfg.get("modules", ["subdomains"])
        port_range: str = cfg.get("port_range", "top-1000")
        timeout_sec: float = float(cfg.get("timeout_seconds", 30))

        run_subs = "subdomains" in modules
        run_ports = "ports" in modules

        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        job.progress = 5
        await s.commit()

    logger.info("Scan %s started for %s (modules=%s)", job_id, domain_name, modules)

    # ── 2. Subdomain enumeration ──────────────────────────────────────────────
    sub_results: list[SubdomainResult] = []
    error: Optional[Exception] = None

    if run_subs and not error:
        try:
            sub_results = await enumerate_subdomains(domain_name)
            if run_ports:
                await _set_progress(job_id, 30)  # subs + ports path
            else:
                await _set_progress(job_id, 60)  # subs-only path
        except Exception as exc:
            logger.exception("Scan %s failed during subdomain enumeration", job_id)
            error = exc

    # ── 3. Port scanning ──────────────────────────────────────────────────────
    port_results: list[PortResult] = []

    if run_ports and not error:
        # Collect targets: resolved IPs from subdomains + root domain
        if run_subs:
            await _set_progress(job_id, 60)  # subs done, starting ports
            targets: list[str] = [domain_name] + [
                r.resolved_ip for r in sub_results if r.resolved_ip
            ]
        else:
            await _set_progress(job_id, 40)  # ports-only path
            targets = [domain_name]

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique_targets: list[str] = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                unique_targets.append(t)

        try:
            for host in unique_targets:
                host_results = await scan_ports(host, port_range, timeout_sec)
                port_results.extend(host_results)
                logger.debug(
                    "Scan %s: %d open ports on %s", job_id, len(host_results), host
                )
            await _set_progress(job_id, 90 if run_subs else 90)
        except Exception as exc:
            logger.exception("Scan %s failed during port scan", job_id)
            error = exc
    elif run_subs and not error:
        # Subdomains-only: DNS resolution already done inside enumerate_subdomains
        await _set_progress(job_id, 90)

    # ── 4. Persist results ────────────────────────────────────────────────────
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
            for r in sub_results:
                s.add(Subdomain(
                    scan_job_id=job_id,
                    domain_id=domain_id,
                    hostname=r.hostname,
                    source=r.source,
                    resolved_ip=r.resolved_ip,
                ))
            for r in port_results:
                # Only persist open ports
                s.add(Port(
                    scan_job_id=job_id,
                    domain_id=domain_id,
                    host=r.host,
                    port=r.port,
                    protocol=r.protocol,
                    state=r.state,
                    service=r.service,
                    banner=r.banner,
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
                    "subdomains_found": len(sub_results),
                    "open_ports_found": len(port_results),
                },
            ))
            logger.info(
                "Scan %s completed: %d subdomains, %d open ports for %s",
                job_id, len(sub_results), len(port_results), domain_name,
            )

        await s.commit()
