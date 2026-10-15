"""Topes del ejecutor: hosts, subdominios, tiempo total y escaneos simultáneos. Lo que se corta se informa."""
import asyncio

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_engine
from app.models.finding import Finding
from app.models.http_fingerprint import HttpFingerprint
from app.models.port import Port
from app.models.scan_job import ScanJob
from app.models.subdomain import Subdomain
from app.recon import subdomains
from app.recon.fingerprint import HttpFingerprintResult
from app.recon.ports import PortResult
from app.services import scan_runner
from app.services.scan_notes import ScanNotes

from .helpers import make_domain, make_job, make_user

pytestmark = [pytest.mark.db, pytest.mark.usefixtures("clean_db")]

PUBLIC = [f"93.184.216.{n}" for n in range(10, 15)]


async def _job_and_notes(job_id):
    async with AsyncSession(get_engine()) as s:
        job = await s.get(ScanJob, job_id)
        notes = {
            f.evidence["reason"]: f.evidence
            for f in await s.scalars(select(Finding).where(Finding.scan_job_id == job_id, Finding.category == "other"))
            if "host" not in f.evidence
        }
        return job, notes


def _fake_subdomains(monkeypatch, names, addresses):
    async def crtsh(domain, **_):
        return set(names)

    async def resolve(hostname):
        return [addresses[hostname]] if hostname in addresses else []

    monkeypatch.setattr(subdomains, "_fetch_crtsh", crtsh)
    monkeypatch.setattr(subdomains, "_resolve_a", resolve)


# ── Notas ────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_scan_notes_keep_one_entry_per_reason_and_host():
    notes = ScanNotes()
    notes.skip_host("a.example.com", "non_public_address")
    notes.skip_host("a.example.com", "non_public_address")
    notes.skip_host("b.example.com", "non_public_address")
    notes.note("time_limit", phase="port scan", seconds=900)
    notes.note("time_limit", phase="fingerprinting", seconds=900)
    assert len(notes) == 3
    assert notes.is_skipped("a.example.com") and not notes.is_skipped("c.example.com")
    assert [n["reason"] for n in notes.items()] == ["non_public_address", "non_public_address", "time_limit"]
    assert notes.items()[2]["phase"] == "port scan"


# ── Subdominios y hosts ──────────────────────────────────────────────────────────────────────────────────────────

async def test_only_the_first_subdomains_are_resolved_and_the_report_says_so(monkeypatch):
    monkeypatch.setattr(settings, "SCAN_MAX_SUBDOMAINS", 3)
    user, _ = await make_user()
    domain = await make_domain(user, "example.com")
    job = await make_job(user, domain, config={"modules": ["subdomains"], "port_range": "top-100", "timeout_seconds": 5})
    names = ["example.com", "www.example.com", "mail.example.com", "a.b.example.com", "x.y.z.example.com", "zz.example.com"]
    _fake_subdomains(monkeypatch, names, {})

    await scan_runner.run_scan(job.id)

    job_row, notes = await _job_and_notes(job.id)
    assert job_row.status == "completed"
    async with AsyncSession(get_engine()) as s:
        kept = sorted(r.hostname for r in await s.scalars(select(Subdomain).where(Subdomain.scan_job_id == job.id)))
    assert kept == ["example.com", "mail.example.com", "www.example.com"]  # los más cortos primero
    assert notes["limit_subdomains"] == {"reason": "limit_subdomains", "found": 6, "kept": 3, "limit": 3}


async def test_the_number_of_hosts_actually_scanned_is_capped(monkeypatch):
    monkeypatch.setattr(settings, "SCAN_MAX_HOSTS", 2)
    user, _ = await make_user()
    domain = await make_domain(user, "example.com")
    job = await make_job(user, domain, config={"modules": ["subdomains", "ports"], "port_range": "top-100", "timeout_seconds": 5})
    _fake_subdomains(monkeypatch, [f"h{i}.example.com" for i in range(5)], {f"h{i}.example.com": PUBLIC[i] for i in range(5)})
    scanned: list[str] = []

    async def fake_scan_ports(host, port_range, timeout):
        scanned.append(host)
        return []

    monkeypatch.setattr(scan_runner, "scan_ports", fake_scan_ports)

    await scan_runner.run_scan(job.id)

    _, notes = await _job_and_notes(job.id)
    assert scanned == ["example.com", PUBLIC[0]]
    assert notes["limit_hosts"] == {"reason": "limit_hosts", "phase": "port scan", "total": 6, "scanned": 2, "limit": 2}


async def test_the_number_of_hosts_fingerprinted_is_capped_too(monkeypatch):
    monkeypatch.setattr(settings, "SCAN_MAX_HOSTS", 2)
    user, _ = await make_user()
    domain = await make_domain(user, "example.com")
    job = await make_job(user, domain, config={"modules": ["subdomains", "fingerprint"], "port_range": "top-100", "timeout_seconds": 5})
    _fake_subdomains(monkeypatch, [f"h{i}.example.com" for i in range(5)], {f"h{i}.example.com": PUBLIC[i] for i in range(5)})
    asked: list[str] = []

    async def fake_http(url, timeout, scope):
        asked.append(url)
        return None

    async def fake_tls(host, timeout):
        asked.append(f"tls://{host}")
        return None

    monkeypatch.setattr(scan_runner, "fingerprint_http", fake_http)
    monkeypatch.setattr(scan_runner, "fingerprint_tls", fake_tls)

    await scan_runner.run_scan(job.id)

    _, notes = await _job_and_notes(job.id)
    assert sorted({url.split("//")[1] for url in asked}) == ["example.com", "h0.example.com"]
    assert notes["limit_hosts"] == {"reason": "limit_hosts", "phase": "fingerprinting", "total": 6, "scanned": 2, "limit": 2}


# ── Tiempo total ─────────────────────────────────────────────────────────────────────────────────────────────────

async def test_a_scan_that_reaches_the_time_limit_keeps_what_it_has_and_says_it_is_partial(monkeypatch):
    monkeypatch.setattr(settings, "SCAN_MAX_SECONDS", 1)
    user, _ = await make_user()
    domain = await make_domain(user, "example.com")
    job = await make_job(user, domain, config={"modules": ["subdomains", "ports"], "port_range": "top-100", "timeout_seconds": 5})
    _fake_subdomains(monkeypatch, ["example.com", "slow.example.com"], {"example.com": PUBLIC[0], "slow.example.com": PUBLIC[1]})

    async def fake_scan_ports(host, port_range, timeout):
        if host == "example.com":
            return [PortResult(host=host, port=22, state="open", service="ssh", banner="SSH-2.0-OpenSSH")]
        await asyncio.sleep(30)  # un host que nunca contesta
        return []

    monkeypatch.setattr(scan_runner, "scan_ports", fake_scan_ports)
    started = asyncio.get_running_loop().time()

    await scan_runner.run_scan(job.id)

    assert asyncio.get_running_loop().time() - started < 10
    job_row, notes = await _job_and_notes(job.id)
    assert job_row.status == "completed"
    assert notes["time_limit"]["phase"] == "port scan" and notes["time_limit"]["seconds"] == 1
    async with AsyncSession(get_engine()) as s:
        ports = [(p.host, p.port) for p in await s.scalars(select(Port).where(Port.scan_job_id == job.id))]
    assert ports == [("example.com", 22)]


async def test_what_was_read_before_the_time_ran_out_in_a_host_is_kept(monkeypatch):
    monkeypatch.setattr(settings, "SCAN_MAX_SECONDS", 1)
    user, _ = await make_user()
    domain = await make_domain(user, "example.com")
    job = await make_job(user, domain, config={"modules": ["fingerprint"], "port_range": "top-100", "timeout_seconds": 5})

    async def fake_http(url, timeout, scope):
        return HttpFingerprintResult(url=url, status_code=200, server_header="nginx", title="Home", response_headers={"server": "nginx"})

    async def slow_tls(host, timeout):
        await asyncio.sleep(30)

    monkeypatch.setattr(scan_runner, "fingerprint_http", fake_http)
    monkeypatch.setattr(scan_runner, "fingerprint_tls", slow_tls)

    await scan_runner.run_scan(job.id)

    job_row, notes = await _job_and_notes(job.id)
    assert job_row.status == "completed" and notes["time_limit"]["phase"] == "fingerprinting"
    async with AsyncSession(get_engine()) as s:
        urls = sorted(f.url for f in await s.scalars(select(HttpFingerprint).where(HttpFingerprint.scan_job_id == job.id)))
    assert urls == ["http://example.com", "https://example.com"]


async def test_within_limit_runs_the_work_or_notes_the_timeout():
    notes = ScanNotes()
    loop = asyncio.get_running_loop()

    async def quick():
        return 7

    assert await scan_runner._within_limit(loop.time() + 5, notes, "x", quick) == (7, True)
    assert len(notes) == 0
    assert await scan_runner._within_limit(loop.time() - 1, notes, "x", quick) == (None, False)  # sin tiempo: ni empieza

    async def slow():
        await asyncio.sleep(10)

    assert await scan_runner._within_limit(loop.time() + 0.2, notes, "slow", slow) == (None, False)
    assert notes.items()[0]["reason"] == "time_limit"


# ── Simultáneos ──────────────────────────────────────────────────────────────────────────────────────────────────

async def test_only_the_allowed_number_of_scans_run_at_once_the_rest_wait_queued(monkeypatch):
    monkeypatch.setattr(settings, "SCAN_MAX_CONCURRENT", 1)
    monkeypatch.setattr(scan_runner, "_slots", None)  # el semáforo se crea con el valor vigente
    user, _ = await make_user()
    domain = await make_domain(user, "example.com")
    config = {"modules": ["ports"], "port_range": "top-100", "timeout_seconds": 5}
    first, second = await make_job(user, domain, config=config), await make_job(user, domain, config=config)
    release = asyncio.Event()
    running_now = 0
    peak = 0

    async def fake_scan_ports(host, port_range, timeout):
        nonlocal running_now, peak
        running_now += 1
        peak = max(peak, running_now)
        await release.wait()
        running_now -= 1
        return []

    monkeypatch.setattr(scan_runner, "scan_ports", fake_scan_ports)

    tasks = [asyncio.create_task(scan_runner.run_scan(j.id)) for j in (first, second)]
    await asyncio.sleep(0.5)

    async with AsyncSession(get_engine()) as s:
        statuses = sorted([(await s.get(ScanJob, first.id)).status, (await s.get(ScanJob, second.id)).status])
    assert statuses == ["queued", "running"]

    release.set()
    await asyncio.gather(*tasks)
    assert peak == 1
    async with AsyncSession(get_engine()) as s:
        assert [(await s.get(ScanJob, j.id)).status for j in (first, second)] == ["completed", "completed"]
    monkeypatch.setattr(scan_runner, "_slots", None)
