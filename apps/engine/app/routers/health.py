from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_session

router = APIRouter(tags=["health"])


@router.get("/health")
async def health(session: AsyncSession = Depends(get_session)):
    try:
        await session.execute(text("SELECT 1"))
        return {"status": "ok", "db": "connected"}
    except Exception:
        from fastapi import Response
        return Response(
            content='{"status":"error","db":"unavailable"}',
            status_code=503,
            media_type="application/json",
        )
