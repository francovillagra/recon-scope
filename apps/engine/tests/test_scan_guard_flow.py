"""De punta a punta (API -> runner -> base): un dominio verificado cuyo DNS apunta adentro no hace que el motor
mire su red, y el informe lo dice."""
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_engine
from app.models.domain import Domain
from app.recon import ports, subdomains
from app.routers import domains as domains_router
from app.services import scan_runner

from .helpers import make_domain, make_job, make_user
from .netfakes import LocalServer, fake_dns

pytestmark = [pytest.mark.db, pytest.mark.usefixtures("clean_db")]

PUBLIC_IP = "93.184.216.34"


def _skipped_hosts(detail: dict) -> dict:
    return {
        f["evidence"]["host"]: f["evidence"]["reason"]
        for f in detail["findings"]
        if f["category"] == "other" and f["severity"] == "info" and "reason" in f["evidence"]
    }


async def test_a_verified_domain_pointing_to_loopback_is_not_scanned_and_the_report_says_why(client, monkeypatch):
    user, headers = await make_user()
    domain = await make_domain(user, "evil.test")
    fake_dns(monkeypatch, {"evil.test": ["127.0.0.1"]})

    async with LocalServer(banner=b"SSH-2.0-INTERNAL-CANARY\r\n") as internal:
        monkeypatch.setattr(ports, "_ports_for_range", lambda _: [internal.port])
        res = await client.post(
            "/api/v1/scans",
            json={"domain_id": str(domain.id), "modules": ["ports", "fingerprint"], "timeout_seconds": 3},
            headers=headers,
        )
        assert res.status_code == 201
        detail = (await client.get(f"/api/v1/scans/{res.json()['job_id']}", headers=headers)).json()

        assert internal.connections == 0, "el motor se conectó a un servicio de la red interna"

    assert detail["job"]["status"] == "completed", detail["job"]["error_message"]
    assert detail["ports"] == [] and detail["http_fingerprints"] == [] and detail["tls_certificates"] == []
    assert _skipped_hosts(detail) == {"evil.test": "non_public_address"}
    assert "INTERNAL-CANARY" not in str(detail)


async def test_the_same_scan_with_private_targets_allowed_reports_the_service(client, monkeypatch):
    """Control: la configuración para redes propias sigue funcionando."""
    monkeypatch.setattr(settings, "ALLOW_PRIVATE_TARGETS", True)
    user, headers = await make_user()
    domain = await make_domain(user, "lab.test")
    fake_dns(monkeypatch, {"lab.test": ["127.0.0.1"]})

    async with LocalServer(banner=b"SSH-2.0-OpenSSH_9.6\r\n") as server:
        monkeypatch.setattr(ports, "_ports_for_range", lambda _: [server.port])
        res = await client.post(
            "/api/v1/scans", json={"domain_id": str(domain.id), "modules": ["ports"], "timeout_seconds": 3}, headers=headers
        )
        detail = (await client.get(f"/api/v1/scans/{res.json()['job_id']}", headers=headers)).json()

    assert detail["job"]["status"] == "completed", detail["job"]["error_message"]
    assert [(p["host"], p["port"], p["banner"]) for p in detail["ports"]] == [("lab.test", server.port, "SSH-2.0-OpenSSH_9.6")]
    assert _skipped_hosts(detail) == {}


async def test_subdomains_that_resolve_inside_are_not_scanned_and_do_not_show_their_address(monkeypatch):
    user, _ = await make_user()
    domain = await make_domain(user, "example.com")
    job = await make_job(user, domain, config={"modules": ["subdomains", "ports"], "port_range": "top-100", "timeout_seconds": 3})

    async def crtsh(name, **_):
        return {"pub.example.com", "internal.example.com", "meta.example.com"}

    async def resolve(hostname):
        return {"pub.example.com": [PUBLIC_IP], "internal.example.com": ["10.9.8.7"], "meta.example.com": ["169.254.169.254"]}[hostname]

    scanned: list[str] = []

    async def fake_scan_ports(host, port_range, timeout):
        scanned.append(host)
        return []

    monkeypatch.setattr(subdomains, "_fetch_crtsh", crtsh)
    monkeypatch.setattr(subdomains, "_resolve_a", resolve)
    monkeypatch.setattr(scan_runner, "scan_ports", fake_scan_ports)

    await scan_runner.run_scan(job.id)

    assert scanned == ["example.com", PUBLIC_IP]  # ni 10.9.8.7 ni 169.254.169.254
    async with AsyncSession(get_engine()) as s:
        from sqlalchemy import select

        from app.models.finding import Finding
        from app.models.scan_job import ScanJob
        from app.models.subdomain import Subdomain

        assert (await s.get(ScanJob, job.id)).status == "completed"
        rows = {r.hostname: r.resolved_ip for r in await s.scalars(select(Subdomain).where(Subdomain.scan_job_id == job.id))}
        assert {h: (str(ip) if ip else None) for h, ip in rows.items()} == {
            "pub.example.com": PUBLIC_IP, "internal.example.com": None, "meta.example.com": None,
        }
        found = {
            (f.evidence["host"], f.evidence["reason"])
            for f in await s.scalars(select(Finding).where(Finding.scan_job_id == job.id, Finding.category == "other"))
        }
        assert found == {("internal.example.com", "non_public_address"), ("meta.example.com", "non_public_address")}


async def test_http_verification_of_a_domain_that_points_inside_explains_the_problem(client, monkeypatch):
    user, headers = await make_user()
    domain = await make_domain(user, "victim.test", verified=False)
    fake_dns(monkeypatch, {"victim.test": ["127.0.0.1"]})

    res = await client.post(f"/api/v1/domains/{domain.id}/verify", json={"method": "well_known_file"}, headers=headers)

    assert res.status_code == 200
    body = res.json()
    assert body["domain"]["verification_status"] == "failed"
    assert "non-public address" in body["error"] and "DNS TXT" in body["error"]


async def test_dns_txt_verification_does_not_depend_on_where_the_domain_points(client, monkeypatch):
    """El TXT se consulta al resolvedor, no al servidor del dominio: un dominio que apunta adentro puede verificarse por DNS."""
    user, headers = await make_user()
    domain = await make_domain(user, "victim.test", verified=False)

    async def txt_ok(name, token):
        return True

    monkeypatch.setattr(domains_router, "verify_dns_txt", txt_ok)
    res = await client.post(f"/api/v1/domains/{domain.id}/verify", json={"method": "dns_txt"}, headers=headers)

    assert res.json()["domain"]["verification_status"] == "verified"
    async with AsyncSession(get_engine()) as s:
        assert (await s.get(Domain, domain.id)).verification_status == "verified"
