import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_engine
from app.models.scan_job import ScanJob
from app.services.scan_runner import recover_stale_jobs

from .helpers import make_domain, make_job, make_user

pytestmark = [pytest.mark.db, pytest.mark.usefixtures("clean_db")]


async def _age(job_id, hours):
    async with get_engine().begin() as conn:
        await conn.execute(text("UPDATE scan_jobs SET created_at = now() - make_interval(hours => :h) WHERE id = :id"), {"h": hours, "id": job_id})


async def _status(job_id):
    async with AsyncSession(get_engine()) as s:
        job = await s.get(ScanJob, job_id)
        return job.status, job.error_message


async def test_recover_stale_jobs_only_closes_old_unfinished_ones(clean_db):
    user, _ = await make_user()
    domain = await make_domain(user)
    old_running = await make_job(user, domain, status="running")
    old_queued = await make_job(user, domain, status="queued")
    fresh_running = await make_job(user, domain, status="running")
    old_completed = await make_job(user, domain, status="completed")
    for job in (old_running, old_queued, old_completed):
        await _age(job.id, 5)

    assert await recover_stale_jobs() == 2

    assert (await _status(old_running.id))[0] == "failed"
    assert (await _status(old_queued.id))[0] == "failed"
    assert "interrupted" in (await _status(old_running.id))[1]
    assert (await _status(fresh_running.id))[0] == "running"
    assert (await _status(old_completed.id))[0] == "completed"
