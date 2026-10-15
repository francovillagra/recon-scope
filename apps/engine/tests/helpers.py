"""Utilidades de prueba: crear usuarios, dominios y escaneos directo en la base."""
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_engine
from app.models.domain import Domain
from app.models.scan_job import ScanJob
from app.models.user import User
from app.services.auth_service import create_access_token


async def make_user(email: str = "ana@example.com") -> tuple[User, dict]:
    async with AsyncSession(get_engine()) as s:
        user = User(email=email, password_hash="not-a-real-hash")
        s.add(user)
        await s.commit()
        await s.refresh(user)
    token = create_access_token(user.id, user.email, user.role)
    return user, {"Authorization": f"Bearer {token}"}


async def make_domain(user: User, name: str = "example.com", verified: bool = True) -> Domain:
    async with AsyncSession(get_engine()) as s:
        domain = Domain(
            user_id=user.id,
            domain=name,
            verification_token=f"recon-verify-{uuid.uuid4()}",
            verification_status="verified" if verified else "pending",
        )
        s.add(domain)
        await s.commit()
        await s.refresh(domain)
    return domain


async def make_job(user: User, domain: Domain, config: dict | None = None, status: str = "queued") -> ScanJob:
    async with AsyncSession(get_engine()) as s:
        job = ScanJob(
            domain_id=domain.id,
            user_id=user.id,
            target=domain.domain,
            config=config or {"modules": ["subdomains"], "port_range": "top-100", "timeout_seconds": 5},
            status=status,
        )
        s.add(job)
        await s.commit()
        await s.refresh(job)
    return job
