"""Los hallazgos salen de lo más grave a lo menos grave (ordenar el texto de la severidad daba critical, high,
info, low, medium: "info" quedaba entre "high" y "low")."""
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_engine
from app.models.finding import Finding

from .helpers import make_domain, make_job, make_user

pytestmark = [pytest.mark.db, pytest.mark.usefixtures("clean_db")]

SEVERITIES = ["info", "low", "medium", "high", "critical", "low", "high", "info"]
EXPECTED = ["critical", "high", "high", "medium", "low", "low", "info", "info"]


async def _scan_with_findings():
    user, headers = await make_user()
    domain = await make_domain(user)
    job = await make_job(user, domain, status="completed")
    async with AsyncSession(get_engine()) as s:
        for i, severity in enumerate(SEVERITIES):
            s.add(Finding(scan_job_id=job.id, domain_id=domain.id, category="other", severity=severity, title=f"hallazgo {i}"))
        await s.commit()
    return job, headers


async def test_scan_detail_lists_findings_most_severe_first(client):
    job, headers = await _scan_with_findings()

    res = await client.get(f"/api/v1/scans/{job.id}", headers=headers)

    assert [f["severity"] for f in res.json()["findings"]] == EXPECTED


async def test_json_export_lists_findings_most_severe_first(client):
    job, headers = await _scan_with_findings()

    res = await client.get(f"/api/v1/scans/{job.id}/export/json", headers=headers)

    assert [f["severity"] for f in res.json()["findings"]] == EXPECTED
