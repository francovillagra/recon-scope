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
import asyncio
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Awaitable, Callable, Optional, TypeVar

import httpx
from sqlalchemy import func, update
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
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
from app.recon.netguard import BlockedTarget
from app.recon.ports import PortResult, scan_ports
from app.recon.sanitize import clean_json, clean_text
from app.recon.subdomains import CrtShTooLarge, SubdomainResult, enumerate_subdomains
from app.services.findings_engine import generate_findings
from app.services.scan_notes import ScanNotes

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Cuántos escaneos corren a la vez en este proceso. Se crea al primer uso, ya dentro del bucle de eventos.
_slots: Optional[asyncio.Semaphore] = None


def _scan_slots() -> asyncio.Semaphore:
    global _slots
    if _slots is None:
        _slots = asyncio.Semaphore(max(1, settings.SCAN_MAX_CONCURRENT))
    return _slots


async def _within_limit(
    deadline: float, notes: ScanNotes, phase: str, work: Callable[[], Awaitable[T]]
) -> tuple[Optional[T], bool]:
    """Corre `work` sin pasar del tope de tiempo del escaneo. Devuelve (resultado, completó).
    Si se acaba el tiempo, lo anota para el informe y devuelve (None, False): lo ya reunido se guarda como parcial."""
    remaining = deadline - time.monotonic()
    if remaining > 0:
        try:
            async with asyncio.timeout(remaining):
                return await work(), True
        except TimeoutError:
            pass
    notes.note("time_limit", phase=phase, seconds=settings.SCAN_MAX_SECONDS)
    return None, False


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


def _public_error(phase: str, exc: Exception) -> str:
    """Mensaje para el usuario: la causa técnica queda en el log y en el registro de auditoría, no en la API."""
    if phase == "subdomain enumeration" and isinstance(exc, httpx.HTTPError):
        return "Subdomain enumeration failed: the certificate transparency source (crt.sh) is unavailable. Try again later."
    if isinstance(exc, CrtShTooLarge):
        return "Subdomain enumeration failed: this domain has too many certificates in the transparency logs to list them. Run the other modules on their own."
    return f"The {phase} step failed. Try again, or run fewer modules."


async def _mark_failed(job_id: uuid.UUID, user_id: uuid.UUID, target: str, public_message: str, detail: str) -> None:
    try:
        async with AsyncSession(get_engine()) as s:
            job = await s.get(ScanJob, job_id)
            if job is None:
                return
            job.status = "failed"
            job.error_message = public_message
            job.completed_at = datetime.now(timezone.utc)
            s.add(AuditLog(
                user_id=user_id,
                action="scan_failed",
                target=target,
                metadata_={"job_id": str(job_id), "error": clean_text(detail)[:200]},
            ))
            await s.commit()
    except Exception:
        logger.exception("Scan %s: could not record the failure", job_id)


async def recover_stale_jobs() -> int:
    """Marca como fallidos los escaneos que quedaron 'queued'/'running' sin que nadie los esté ejecutando."""
    max_age = timedelta(seconds=settings.SCAN_MAX_SECONDS * 2 + 60)
    async with AsyncSession(get_engine()) as s:
        result = await s.execute(
            update(ScanJob)
            .where(
                ScanJob.status.in_(("queued", "running")),
                func.coalesce(ScanJob.started_at, ScanJob.created_at) < func.now() - max_age,
            )
            .values(
                status="failed",
                error_message="The scan was interrupted (the server restarted or the job timed out). Start it again.",
                completed_at=func.now(),
            )
        )
        await s.commit()
        return result.rowcount or 0


async def run_scan(job_id: uuid.UUID) -> None:
    """Corre el escaneo cuando hay un lugar libre (SCAN_MAX_CONCURRENT). Mientras espera sigue en 'queued'."""
    async with _scan_slots():
        await _run_scan(job_id)


async def _fingerprint_host(
    host: str,
    domain_name: str,
    timeout_sec: float,
    fp_results: list[tuple[HttpFingerprintResult, list[TechResult]]],
    tls_results: list[TlsResult],
) -> None:
    """Agrega lo que encuentre a las listas a medida que lo obtiene: si se acaba el tiempo a mitad de un host,
    lo que ya se leyó no se pierde."""
    for scheme in ("http", "https"):
        fp = await fingerprint_http(f"{scheme}://{host}", timeout_sec, domain_name)
        if fp is not None:
            fp_results.append((fp, await detect_technologies(fp)))
    tls = await fingerprint_tls(host, timeout_sec)
    if tls is not None:
        tls_results.append(tls)


async def _run_scan(job_id: uuid.UUID) -> None:
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

    deadline = time.monotonic() + settings.SCAN_MAX_SECONDS
    max_hosts = settings.SCAN_MAX_HOSTS
    error: Optional[Exception] = None
    error_phase = ""
    # Lo que el motor no hizo (destinos internos omitidos, topes alcanzados, resultado parcial). Se informa como
    # hallazgos informativos: sin eso, el informe de un dominio que apunta a una red interna saldría vacío sin explicación.
    notes = ScanNotes()

    # ── 2. Subdomain enumeration ──────────────────────────────────────────────
    sub_results: list[SubdomainResult] = []

    if run_subs and not error:
        try:
            enumeration, _ = await _within_limit(
                deadline, notes, "subdomain enumeration",
                lambda: enumerate_subdomains(domain_name, settings.SCAN_MAX_SUBDOMAINS),
            )
            if enumeration is not None:
                sub_results = enumeration.results
                if enumeration.total_found > len(sub_results):
                    notes.note(
                        "limit_subdomains",
                        found=enumeration.total_found, kept=len(sub_results), limit=settings.SCAN_MAX_SUBDOMAINS,
                    )
                for r in sub_results:
                    if r.skipped_reason:
                        notes.skip_host(r.hostname, r.skipped_reason)
            if p_subs is not None:
                await _set_progress(job_id, p_subs)
        except Exception as exc:
            logger.exception("Scan %s failed during subdomain enumeration", job_id)
            error, error_phase = exc, "subdomain enumeration"

    # ── 3. Port scanning ──────────────────────────────────────────────────────
    port_results: list[PortResult] = []

    if run_ports and not error:
        # El dominio por nombre y, de los subdominios, las IP (varios nombres suelen compartir una): sin repetir.
        targets = [domain_name] + ([r.resolved_ip for r in sub_results if r.resolved_ip] if run_subs else [])
        unique_targets = list(dict.fromkeys(targets))
        if len(unique_targets) > max_hosts:
            notes.note("limit_hosts", phase="port scan", total=len(unique_targets), scanned=max_hosts, limit=max_hosts)
            unique_targets = unique_targets[:max_hosts]

        try:
            for host in unique_targets:
                try:
                    results, completed = await _within_limit(
                        deadline, notes, "port scan", lambda h=host: scan_ports(h, port_range, timeout_sec)
                    )
                except BlockedTarget as blocked:
                    notes.skip_host(host, blocked.reason)
                    continue
                if not completed:
                    break
                port_results.extend(results)
                logger.debug("Scan %s: %d open ports on %s", job_id, len(results), host)
            if p_ports is not None:
                await _set_progress(job_id, p_ports)
        except Exception as exc:
            logger.exception("Scan %s failed during port scan", job_id)
            error, error_phase = exc, "port scan"

    elif run_subs and not run_fp and not error:
        # Subs-only: advance to pre-persist checkpoint
        await _set_progress(job_id, 90)

    # ── 4. Fingerprinting ─────────────────────────────────────────────────────
    fp_results: list[tuple[HttpFingerprintResult, list[TechResult]]] = []
    tls_results: list[TlsResult] = []

    if run_fp and not error:
        # Targets: subdomain hostnames (not IPs) + root domain, sin repetir y sin los que ya se sabe que apuntan adentro
        fp_hosts = [domain_name] + ([r.hostname for r in sub_results] if run_subs else [])
        unique_fp_hosts = [h for h in dict.fromkeys(fp_hosts) if not notes.is_skipped(h)]
        if len(unique_fp_hosts) > max_hosts:
            notes.note("limit_hosts", phase="fingerprinting", total=len(unique_fp_hosts), scanned=max_hosts, limit=max_hosts)
            unique_fp_hosts = unique_fp_hosts[:max_hosts]

        try:
            for host in unique_fp_hosts:
                try:
                    _, completed = await _within_limit(
                        deadline, notes, "fingerprinting",
                        lambda h=host: _fingerprint_host(h, domain_name, timeout_sec, fp_results, tls_results),
                    )
                except BlockedTarget as blocked:
                    notes.skip_host(host, blocked.reason)
                    continue
                if not completed:
                    break

            if p_fp is not None:
                await _set_progress(job_id, p_fp)
        except Exception as exc:
            logger.exception("Scan %s failed during fingerprinting", job_id)
            error, error_phase = exc, "fingerprinting"

    elif run_ports and not run_fp and not error:
        # Ports-only: advance to pre-persist checkpoint
        await _set_progress(job_id, 90)

    # ── 5. Persist results ────────────────────────────────────────────────────
    if error:
        logger.warning("Scan %s failed: %s", job_id, error)
        await _mark_failed(job_id, user_id, domain_name, _public_error(error_phase, error), str(error))
        return

    try:
        await _persist_results(
            job_id, user_id, domain_id, domain_name,
            sub_results, port_results, fp_results, tls_results, notes,
        )
    except Exception as exc:
        logger.exception("Scan %s: saving the results failed", job_id)
        await _mark_failed(job_id, user_id, domain_name, _public_error("result saving", exc), str(exc))


async def _persist_results(
    job_id: uuid.UUID,
    user_id: uuid.UUID,
    domain_id: uuid.UUID,
    domain_name: str,
    sub_results: list[SubdomainResult],
    port_results: list[PortResult],
    fp_results: list[tuple[HttpFingerprintResult, list[TechResult]]],
    tls_results: list[TlsResult],
    notes: ScanNotes,
) -> None:
    async with AsyncSession(get_engine()) as s:
        job = await s.get(ScanJob, job_id)
        if not job:
            return

        for r in sub_results:
            s.add(Subdomain(
                scan_job_id=job_id, domain_id=domain_id,
                hostname=clean_text(r.hostname), source=r.source, resolved_ip=r.resolved_ip,
            ))
        for r in port_results:
            s.add(Port(
                scan_job_id=job_id, domain_id=domain_id,
                host=clean_text(r.host), port=r.port, protocol=r.protocol,
                state=r.state, service=r.service, banner=clean_text(r.banner),
            ))
        for fp, techs in fp_results:
            fp_row = HttpFingerprint(
                scan_job_id=job_id, domain_id=domain_id,
                url=clean_text(fp.url), status_code=fp.status_code,
                server_header=clean_text(fp.server_header), title=clean_text(fp.title),
                response_headers=clean_json(fp.response_headers),
            )
            s.add(fp_row)
            await s.flush()  # get fp_row.id
            for t in techs:
                s.add(Technology(
                    scan_job_id=job_id, domain_id=domain_id,
                    http_fingerprint_id=fp_row.id,
                    name=t.name, category=t.category,
                    version=clean_text(t.version), confidence=t.confidence,
                ))
        for tls in tls_results:
            s.add(TlsCertificate(
                scan_job_id=job_id, domain_id=domain_id,
                host=clean_text(tls.host), issuer=clean_text(tls.issuer), subject=clean_text(tls.subject),
                valid_from=tls.valid_from, valid_to=tls.valid_to,
                is_valid=tls.is_valid,
                signature_algorithm=tls.signature_algorithm,
                san=clean_json(tls.san),
            ))

        await s.flush()  # ensure all rows visible before findings query

        # Generate and persist findings
        new_findings = await generate_findings(job_id, domain_id, s, notes)
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
