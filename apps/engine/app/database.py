from typing import AsyncGenerator
from sqlalchemy.engine import URL, make_url
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
)
from app.config import settings


def _make_url(raw: str) -> str:
    """Normalise postgres:// → postgresql+asyncpg:// and strip ssl query param."""
    for prefix in ("postgres://", "postgresql://"):
        if raw.startswith(prefix):
            raw = "postgresql+asyncpg://" + raw[len(prefix):]
            break
    # Strip ssl param — passed via connect_args instead for asyncpg compatibility
    raw = raw.replace("?ssl=require", "").replace("&ssl=require", "")
    return raw


def migration_engine_args(database_url: str, migration_url: str = "") -> tuple[URL, dict]:
    """
    URL síncrona (psycopg2) y connect_args con los que Alembic se conecta.

    Usa MIGRATION_DATABASE_URL si existe; si no, deriva la URL de DATABASE_URL (que es de asyncpg).
    SSL se exige por defecto (`sslmode=require`, lo que necesita Supabase); un Postgres local sin SSL,
    como el de docker-compose, lo indica en la propia URL con `?sslmode=disable`.
    """
    url = make_url(migration_url or database_url)
    if url.drivername in ("postgres", "postgresql", "postgresql+asyncpg"):
        url = url.set(drivername="postgresql+psycopg2")
    query = dict(url.query)
    query.pop("ssl", None)  # parámetro de asyncpg; psycopg2 usa sslmode
    connect_args = {} if "sslmode" in query else {"sslmode": "require"}
    return url.set(query=query), connect_args


_engine = None


def get_engine():
    global _engine
    if _engine is None:
        raw = settings.DATABASE_URL
        connect_args: dict = {"prepared_statement_cache_size": 0}
        if "ssl=require" in raw:
            connect_args["ssl"] = "require"
        _engine = create_async_engine(
            _make_url(raw),
            pool_size=20,
            max_overflow=10,
            connect_args=connect_args,
        )
    return _engine


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSession(get_engine()) as session:
        yield session
