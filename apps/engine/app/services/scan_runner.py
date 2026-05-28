"""
Background job runner — Phase 1 + Phase 2 + Phase 3.

Progress checkpoints by active module set:
  subdomains only:                   5 → 60 → 90 → 100
  ports only:                        5 → 40 → 90 → 100
  fingerprint only:                  5 → 50 → 100
  subdomains + ports:                5 → 30 → 60 → 90 → 100
  subdomains + fingerprint:          5 → 30 → 70 → 100
  ports + fingerprint:               5 → 30 → 70 → 100
  subdomains + ports + fingerprint:  5 → 25 → 50 → 75 → 100
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_engine
from app.models.audit_log import AuditLog
from app.models.http_fingerprint import HttpFingerprint
from app.models.port import Port
from app.models.scan_job import ScanJob
from app.models.subdomain import Subdomain
from app.models.technology import Technology
from app.models.tls_certificate import TlsCertificate
from app.recon.fingerprint import (
    HttpFingerprintResult,
    TechResult,
    TlsResult,
    detect_technologies,
    fingerprint_http,
    fingerprint_tls,
)
from app.recon.ports import PortResult, scan_ports
from app.recon.subdomains import SubdomainResult, enumerate_subdomains
from app.services.findings_engine import generate_findings

logger = logging.getLogger(__name__)


async def _set_progress(job_id: uuid.UUID, progress: int) -> None:
    async with AsyncSession(get_engine()) as s:
        job = await s.get(ScanJob, job_id)
        if job:
            job.progress = progress
            await s.commit()


def _checkpoints(
    run_subs: bool, run_ports: bool, run_fp: bool
) -> tuple[Optional[int], Optional[int], Optional[int]]:
    """Return (after_subs, after_ports, after_fp) progress values."""
    if run_subs and run_ports and run_fp:
        return 25, 50, 75
    if run_subs and run_ports:
        return 30, 90, None
    if run_subs and run_fp:
        return 30, None, 70
    if run_ports and run_fp:
        return None, 30, 70
    if run_subs:
        return 90, None, None   # subs-only: set 90 before persist (historical)
    if run_ports:
        return None, 90, None   # ports-only: set 90 before persist
    if run_fp:
        return None, None, 50
    return None, None, None


async def run_scan(job_id: uuid.UUID) -> None:
    # ── 1. Mark running ───────────────────────────────────────────────────────
    async with AsyncSession(get_engine()) as s:
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
        run_fp = "fingerprint" in modules

        p_subs, p_ports, p_fp = _checkpoints(run_subs, run_ports, run_fp)

        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        job.progress = 5
        await s.commit()

    logger.info("Scan %s started for %s (modules=%s)", job_id, domain_name, modules)

    error: Optional[Exception] = None

    # ── 2. Subdomain enumeration ──────────────────────────────────────────────
    sub_results: list[SubdomainResult] = []

    if run_subs and not error:
        try:
            sub_results = await enumerate_subdomains(domain_name)
            if p_subs is not None:
                await _set_progress(job_id, p_subs)
        except Exception as exc:
            logger.exception("Scan %s failed during subdomain enumeration", job_id)
            error = exc

    # ── 3. Port scanning ──────────────────────────────────────────────────────
    port_results: list[PortResult] = []

    if run_ports and not error:
        if run_subs:
            targets: list[str] = [domain_name] + [
                r.resolved_ip for r in sub_results if r.resolved_ip
            ]
        else:
            targets = [domain_name]

        seen: set[str] = set()
        unique_targets: list[str] = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                unique_targets.append(t)

        try:
            for host in unique_targets:
                results = await scan_ports(host, port_range, timeout_sec)
                port_results.extend(results)
                logger.debug("Scan %s: %d open ports on %s", job_id, len(results), host)
            if p_ports is not None:
                await _set_progress(job_id, p_ports)
        except Exception as exc:
            logger.exception("Scan %s failed during port scan", job_id)
            error = exc

    elif run_subs and not run_fp and not error:
        # Subs-only: advance to pre-persist checkpoint
        await _set_progress(job_id, 90)

    # ── 4. Fingerprinting ─────────────────────────────────────────────────────
    fp_results: list[tuple[HttpFingerprintResult, list[TechResult]]] = []
    tls_results: list[TlsResult] = []

    if run_fp and not error:
        # Targets: subdomain hostnames (not IPs) + root domain
        if run_subs:
            fp_hosts: list[str] = [domain_name] + [r.hostname for r in sub_results]
        else:
            fp_hosts = [domain_name]

        # Deduplicate preserving order
        seen_fp: set[str] = set()
        unique_fp_hosts: list[str] = []
        for h in fp_hosts:
            if h not in seen_fp:
                seen_fp.add(h)
                unique_fp_hosts.append(h)

        try:
            for host in unique_fp_hosts:
                for scheme in ("http", "https"):
                    fp = await fingerprint_http(f"{scheme}://{host}", timeout_sec)
                    if fp is not None:
                        techs = await detect_technologies(fp)
                        fp_results.append((fp, techs))
                tls = await fingerprint_tls(host, timeout_sec)
                if tls is not None:
                    tls_results.append(tls)

            if p_fp is not None:
                await _set_progress(job_id, p_fp)
        except Exception as exc:
            logger.exception("Scan %s failed during fingerprinting", job_id)
            error = exc

    elif run_ports and not run_fp and not error:
        # Ports-only: advance to pre-persist checkpoint
        await _set_progress(job_id, 90)

    # ── 5. Persist results ────────────────────────────────────────────────────
    async with AsyncSession(get_engine()) as s:
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
                metadata_={"job_id": str(job_id), "error": str(error)[:200]},
            ))
            logger.warning("Scan %s failed: %s", job_id, error)
        else:
            for r in sub_results:
                s.add(Subdomain(
                    scan_job_id=job_id, domain_id=domain_id,
                    hostname=r.hostname, source=r.source, resolved_ip=r.resolved_ip,
                ))
            for r in port_results:
                s.add(Port(
                    scan_job_id=job_id, domain_id=domain_id,
                    host=r.host, port=r.port, protocol=r.protocol,
                    state=r.state, service=r.service, banner=r.banner,
                ))
            fp_id_map: dict[str, uuid.UUID] = {}
            for fp, techs in fp_results:
                fp_row = HttpFingerprint(
                    scan_job_id=job_id, domain_id=domain_id,
                    url=fp.url, status_code=fp.status_code,
                    server_header=fp.server_header, title=fp.title,
                    response_headers=fp.response_headers,
                )
                s.add(fp_row)
                await s.flush()  # get fp_row.id
                fp_id_map[fp.url] = fp_row.id
                for t in techs:
                    s.add(Technology(
                        scan_job_id=job_id, domain_id=domain_id,
                        http_fingerprint_id=fp_row.id,
                        name=t.name, category=t.category,
                        version=t.version, confidence=t.confidence,
                    ))
            for tls in tls_results:
                s.add(TlsCertificate(
                    scan_job_id=job_id, domain_id=domain_id,
                    host=tls.host, issuer=tls.issuer, subject=tls.subject,
                    valid_from=tls.valid_from, valid_to=tls.valid_to,
                    is_valid=tls.is_valid,
                    signature_algorithm=tls.signature_algorithm,
                    san=tls.san,
                ))

            await s.flush()  # ensure all rows visible before findings query

            # Generate and persist findings
            new_findings = await generate_findings(job_id, domain_id, s)
            for f in new_findings:
                s.add(f)

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
                    "fingerprints": len(fp_results),
                    "findings": len(new_findings),
                },
            ))
            logger.info(
                "Scan %s completed: %d subs, %d ports, %d fingerprints, %d findings for %s",
                job_id, len(sub_results), len(port_results),
                len(fp_results), len(new_findings), domain_name,
            )

        await s.commit()
