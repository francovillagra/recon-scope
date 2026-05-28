from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
)
from app.config import settings


def _make_url(raw: str) -> str:
    """Normalise postgres:// → postgresql+asyncpg:// for the async driver."""
    for prefix in ("postgres://", "postgresql://"):
        if raw.startswith(prefix):
            return "postgresql+asyncpg://" + raw[len(prefix):]
    return raw


_engine = None


def get_engine():
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            _make_url(settings.DATABASE_URL),
            pool_size=20,
            max_overflow=10,
        )
    return _engine


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSession(get_engine()) as session:
        yield session
