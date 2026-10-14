"""Validación de lo que el cliente puede pedir (módulos, tiempos, dominios) y de los topes por usuario."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_engine
from app.models.scan_job import ScanJob
from app.routers import domains as domains_router
from app.routers import scans as scans_router
from app.schemas.domain import CreateDomainRequest
from app.schemas.scan import CreateScanRequest

from .helpers import make_domain, make_job, make_user

DOMAIN_ID = str(uuid.uuid4())


# ── Esquemas (sin base de datos) ─────────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "body",
    [
        {"timeout_seconds": -1}, {"timeout_seconds": 0}, {"timeout_seconds": 61}, {"timeout_seconds": 1_000_000_000},
        {"modules": []},
        {"modules": ["ports"] * 400},
        {"modules": ["ports", "subdomains", "fingerprint", "ports", "x"]},
        {"modules": ["../../x", "<script>"]},
        {"modules": ["nmap"]},
        {"port_range": "abc"},
        {"modules": ["ports"], "passive_only": True},  # contradicción
    ],
)
def test_invalid_scan_requests_are_rejected(body):
    with pytest.raises(ValidationError):
        CreateScanRequest(domain_id=DOMAIN_ID, **body)


def test_valid_limits_are_accepted_and_modules_lose_their_duplicates():
    req = CreateScanRequest(domain_id=DOMAIN_ID, timeout_seconds=60, modules=["ports", "ports", "fingerprint"])
    assert (req.timeout_seconds, req.modules) == (60, ["ports", "fingerprint"])
    assert CreateScanRequest(domain_id=DOMAIN_ID, timeout_seconds=1).timeout_seconds == 1


@pytest.mark.parametrize(
    "body, passive",
    [
        ({}, True),
        ({"modules": ["subdomains"]}, True),
        ({"modules": ["subdomains"], "passive_only": True}, True),
        ({"modules": ["subdomains"], "passive_only": False}, True),  # lo decide el servidor: no hay módulos activos
        ({"modules": ["ports"]}, False),
        ({"modules": ["fingerprint"]}, False),
        ({"modules": ["subdomains", "ports"], "passive_only": False}, False),
    ],
)
def test_passive_only_is_computed_from_the_modules(body, passive):
    assert CreateScanRequest(domain_id=DOMAIN_ID, **body).passive_only is passive


def test_domain_names_longer_than_dns_allows_are_rejected():
    ok = ".".join(["a" * 61] * 4) + ".com"
    assert len(ok) == 251 and CreateDomainRequest(domain=ok).domain == ok
    too_long = ".".join(["a" * 60] * 6) + ".com"  # 370 caracteres: antes se aceptaba
    assert len(too_long) > 253
    with pytest.raises(ValidationError):
        CreateDomainRequest(domain=too_long)


# ── API (con base de datos) ──────────────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def no_background_scans(monkeypatch):
    """El escaneo no corre de verdad: los trabajos quedan 'queued' y se prueba solo la API."""
    started: list[uuid.UUID] = []

    async def fake_run_scan(job_id):
        started.append(job_id)

    monkeypatch.setattr(scans_router, "run_scan", fake_run_scan)
    return started


async def _post_scan(client, headers, domain, **body):
    return await client.post("/api/v1/scans", json={"domain_id": str(domain.id), **body}, headers=headers)


@pytest.mark.parametrize("body", [{"timeout_seconds": -1}, {"timeout_seconds": 1_000_000_000}, {"modules": ["ports"] * 400}, {"modules": []}])
@pytest.mark.db
@pytest.mark.usefixtures("clean_db")
async def test_the_api_rejects_unbounded_parameters(client, no_background_scans, body):
    user, headers = await make_user()
    domain = await make_domain(user)
    assert (await _post_scan(client, headers, domain, **body)).status_code == 422
    assert no_background_scans == []


@pytest.mark.db
@pytest.mark.usefixtures("clean_db")
async def test_the_config_stored_with_the_job_tells_the_truth_about_passive_only(client, no_background_scans):
    user, headers = await make_user()
    domain = await make_domain(user)
    passive = (await _post_scan(client, headers, domain, modules=["subdomains"])).json()["job_id"]
    active = (await _post_scan(client, headers, domain, modules=["ports", "fingerprint"])).json()["job_id"]
    contradictory = await _post_scan(client, headers, domain, modules=["ports"], passive_only=True)

    async with AsyncSession(get_engine()) as s:
        assert (await s.get(ScanJob, uuid.UUID(passive))).config["passive_only"] is True
        assert (await s.get(ScanJob, uuid.UUID(active))).config["passive_only"] is False
    assert contradictory.status_code == 422


@pytest.mark.db
@pytest.mark.usefixtures("clean_db")
async def test_invalid_requests_do_not_use_up_the_hourly_quota(client, no_background_scans):
    """Doce pedidos a un dominio que no existe gastaban los 10 escaneos por hora."""
    user, headers = await make_user()
    domain = await make_domain(user)
    fake = type("D", (), {"id": uuid.uuid4()})()
    codes = [(await _post_scan(client, headers, fake)).status_code for _ in range(12)]
    assert codes == [404] * 12
    assert (await _post_scan(client, headers, domain)).status_code == 201


@pytest.mark.db
@pytest.mark.usefixtures("clean_db")
async def test_ten_scans_per_hour_and_the_eleventh_gets_retry_after(client, no_background_scans, monkeypatch):
    monkeypatch.setattr(settings, "SCAN_MAX_PER_USER", 100)
    user, headers = await make_user()
    domain = await make_domain(user)
    for _ in range(10):
        assert (await _post_scan(client, headers, domain)).status_code == 201
    res = await _post_scan(client, headers, domain)
    assert res.status_code == 429
    assert int(res.headers["retry-after"]) > 0


@pytest.mark.db
@pytest.mark.usefixtures("clean_db")
async def test_a_user_cannot_have_more_scans_in_progress_than_the_cap(client, no_background_scans, monkeypatch):
    monkeypatch.setattr(settings, "SCAN_MAX_PER_USER", 2)
    user, headers = await make_user()
    domain = await make_domain(user)
    first = (await _post_scan(client, headers, domain)).json()["job_id"]
    assert (await _post_scan(client, headers, domain)).status_code == 201

    blocked = await _post_scan(client, headers, domain)
    assert blocked.status_code == 429 and "in progress" in blocked.json()["detail"]

    async with get_engine().begin() as conn:  # uno termina: queda lugar
        await conn.execute(text("UPDATE scan_jobs SET status = 'completed' WHERE id = :id"), {"id": uuid.UUID(first)})
    assert (await _post_scan(client, headers, domain)).status_code == 201

    other, other_headers = await make_user("otra@example.com")  # el tope es por usuario
    other_domain = await make_domain(other, "otro.example")
    assert (await _post_scan(client, other_headers, other_domain)).status_code == 201


@pytest.mark.db
@pytest.mark.usefixtures("clean_db")
async def test_verification_that_expired_must_be_repeated(client, no_background_scans, monkeypatch):
    monkeypatch.setattr(settings, "VERIFICATION_MAX_AGE_DAYS", 30)
    user, headers = await make_user()
    domain = await make_domain(user, verified=False)
    async with get_engine().begin() as conn:
        await conn.execute(
            text("UPDATE domains SET verification_status='verified', verified_at=:t WHERE id=:id"),
            {"t": datetime.now(timezone.utc) - timedelta(days=31), "id": domain.id},
        )

    expired = await _post_scan(client, headers, domain)
    assert expired.status_code == 422 and "expired" in expired.json()["detail"]

    async def txt_ok(name, token):
        return True

    monkeypatch.setattr(domains_router, "verify_dns_txt", txt_ok)
    again = await client.post(f"/api/v1/domains/{domain.id}/verify", json={"method": "dns_txt"}, headers=headers)
    assert again.json()["already_verified"] is False and again.json()["domain"]["verification_status"] == "verified"
    assert (await _post_scan(client, headers, domain)).status_code == 201

    # y vigente no se vuelve a consultar
    called = []
    monkeypatch.setattr(domains_router, "verify_dns_txt", lambda *a: called.append(a))
    fresh = await client.post(f"/api/v1/domains/{domain.id}/verify", json={"method": "dns_txt"}, headers=headers)
    assert fresh.json()["already_verified"] is True and called == []


@pytest.mark.db
@pytest.mark.usefixtures("clean_db")
async def test_verification_does_not_expire_by_default(client, no_background_scans):
    assert settings.VERIFICATION_MAX_AGE_DAYS == 0
    user, headers = await make_user()
    domain = await make_domain(user)
    async with get_engine().begin() as conn:
        await conn.execute(text("UPDATE domains SET verified_at=:t WHERE id=:id"), {"t": datetime.now(timezone.utc) - timedelta(days=900), "id": domain.id})
    assert (await _post_scan(client, headers, domain)).status_code == 201


@pytest.mark.db
@pytest.mark.usefixtures("clean_db")
async def test_domains_per_user_are_capped(client, monkeypatch):
    monkeypatch.setattr(settings, "MAX_DOMAINS_PER_USER", 3)
    _, headers = await make_user()
    codes = [(await client.post("/api/v1/domains", json={"domain": f"d{i}.example.com"}, headers=headers)).status_code for i in range(4)]
    assert codes == [201, 201, 201, 403]
    _, other = await make_user("otra@example.com")
    assert (await client.post("/api/v1/domains", json={"domain": "d0.example.com"}, headers=other)).status_code == 201


@pytest.mark.db
@pytest.mark.usefixtures("clean_db")
async def test_verification_attempts_are_rate_limited(client, monkeypatch):
    user, headers = await make_user()
    domain = await make_domain(user, verified=False)

    async def txt_missing(name, token):
        return False

    monkeypatch.setattr(domains_router, "verify_dns_txt", txt_missing)
    codes = [(await client.post(f"/api/v1/domains/{domain.id}/verify", json={"method": "dns_txt"}, headers=headers)).status_code for _ in range(21)]
    assert codes == [200] * 20 + [429]
    last = await client.post(f"/api/v1/domains/{domain.id}/verify", json={"method": "dns_txt"}, headers=headers)
    assert int(last.headers["retry-after"]) > 0
