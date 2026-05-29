from typing import AsyncGenerator
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
