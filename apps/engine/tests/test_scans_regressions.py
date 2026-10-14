"""Errores encontrados al probar Recon Scope de punta a punta (ver PR): se reproducen primero, se arreglan después."""
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_engine
from app.models.port import Port
from app.models.scan_job import ScanJob
from app.models.subdomain import Subdomain
from app.recon.ports import PortResult
from app.recon.subdomains import SubdomainEnumeration, SubdomainResult
from app.services import scan_runner

from .helpers import make_domain, make_job, make_user

pytestmark = [pytest.mark.db, pytest.mark.usefixtures("clean_db")]


async def test_scan_detail_with_a_resolved_subdomain_does_not_crash(client):
    """INET llega como ipaddress.IPv4Address y el esquema esperaba str: GET /scans/{id} devolvía 500."""
    user, headers = await make_user()
    domain = await make_domain(user)
    job = await make_job(user, domain, status="completed")
    async with AsyncSession(get_engine()) as s:
        s.add(Subdomain(scan_job_id=job.id, domain_id=domain.id, hostname="www.example.com", source="crt_sh", resolved_ip="203.0.113.7"))
        s.add(Subdomain(scan_job_id=job.id, domain_id=domain.id, hostname="old.example.com", source="crt_sh", resolved_ip=None))
        await s.commit()

    res = await client.get(f"/api/v1/scans/{job.id}", headers=headers)

    assert res.status_code == 200
    by_host = {s["hostname"]: s["resolved_ip"] for s in res.json()["subdomains"]}
    assert by_host == {"www.example.com": "203.0.113.7", "old.example.com": None}


async def test_scan_export_with_a_resolved_subdomain_works(client):
    user, headers = await make_user()
    domain = await make_domain(user)
    job = await make_job(user, domain, status="completed")
    async with AsyncSession(get_engine()) as s:
        s.add(Subdomain(scan_job_id=job.id, domain_id=domain.id, hostname="www.example.com", source="crt_sh", resolved_ip="2001:db8::1"))
        await s.commit()

    res = await client.get(f"/api/v1/scans/{job.id}/export/json", headers=headers)

    assert res.status_code == 200
    assert "2001:db8::1" in res.text


async def test_binary_banner_with_nul_bytes_does_not_leave_the_job_running(monkeypatch):
    """Un servicio con saludo binario (MySQL, por ejemplo) mandaba bytes NUL: PostgreSQL los rechaza al guardar
    y el escaneo quedaba en 'running' para siempre."""
    user, _ = await make_user()
    domain = await make_domain(user)
    job = await make_job(user, domain, config={"modules": ["ports"], "port_range": "top-100", "timeout_seconds": 5})

    async def fake_scan_ports(host, port_range, timeout):
        return [PortResult(host=host, port=3306, state="open", service="mysql", banner="J\x00\x00\x00\n8.0.33\x00abc")]

    monkeypatch.setattr(scan_runner, "scan_ports", fake_scan_ports)

    await scan_runner.run_scan(job.id)

    async with AsyncSession(get_engine()) as s:
        refreshed = await s.get(ScanJob, job.id)
        assert refreshed.status == "completed", refreshed.error_message
        port = (await s.execute(Port.__table__.select().where(Port.scan_job_id == job.id))).first()
        assert "\x00" not in port.banner
        assert "8.0.33" in port.banner


async def test_a_failure_while_saving_marks_the_job_failed_instead_of_running(monkeypatch):
    user, _ = await make_user()
    domain = await make_domain(user)
    job = await make_job(user, domain, config={"modules": ["subdomains"], "port_range": "top-100", "timeout_seconds": 5})

    async def fake_enumerate(domain_name, limit=None):
        # hostname inválido para la columna: fuerza un error al persistir
        return SubdomainEnumeration([SubdomainResult(hostname="x" * 10, resolved_ip="not-an-ip")], 1)

    monkeypatch.setattr(scan_runner, "enumerate_subdomains", fake_enumerate)

    await scan_runner.run_scan(job.id)

    async with AsyncSession(get_engine()) as s:
        refreshed = await s.get(ScanJob, job.id)
        assert refreshed.status == "failed"
        assert refreshed.error_message
