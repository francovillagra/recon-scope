"""
Pruebas del motor de Recon Scope.

- Las pruebas "unitarias" (netguard, esquemas, límites) corren sin base de datos.
- Las marcadas con `db` usan PostgreSQL real: definí TEST_DATABASE_URL (asyncpg) con una base descartable
  cuyo nombre incluya "test" y las migraciones aplicadas (`alembic upgrade head`). Cada prueba vacía las tablas.
"""
import os
import re
import uuid
from urllib.parse import urlsplit

import pytest
import pytest_asyncio

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")

# Settings() se lee al importar `app`: hay que fijar el entorno antes.
os.environ["DATABASE_URL"] = TEST_DATABASE_URL or "postgresql+asyncpg://nobody@127.0.0.1:1/none"
os.environ.setdefault("JWT_SECRET", "test-only-secret-" + uuid.uuid4().hex)
os.environ.setdefault("BCRYPT_ROUNDS", "4")  # rápido; la fuerza real se configura en producción
os.environ.pop("ALLOW_PRIVATE_TARGETS", None)

if TEST_DATABASE_URL and not re.search(r"test", urlsplit(TEST_DATABASE_URL).path, re.IGNORECASE):
    raise RuntimeError('TEST_DATABASE_URL tiene que apuntar a una base descartable cuyo nombre incluya "test".')


def pytest_collection_modifyitems(config, items):
    if TEST_DATABASE_URL:
        return
    skip = pytest.mark.skip(reason="falta TEST_DATABASE_URL (PostgreSQL de pruebas)")
    for item in items:
        if "db" in item.keywords:
            item.add_marker(skip)


@pytest_asyncio.fixture(scope="session")
async def db_engine():
    from app.database import get_engine

    engine = get_engine()
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def clean_db(db_engine):
    from sqlalchemy import text

    async with db_engine.begin() as conn:
        await conn.execute(text(
            "TRUNCATE TABLE findings, technologies, tls_certificates, http_fingerprints, ports, "
            "subdomains, scan_jobs, audit_log, domains, users RESTART IDENTITY CASCADE"
        ))
    yield


@pytest_asyncio.fixture
async def client(clean_db):
    import httpx
    from app.main import app
    from app.ratelimit import reset_all_limiters

    reset_all_limiters()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
