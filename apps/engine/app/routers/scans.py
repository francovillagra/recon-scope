"""
Phase 1 stub — scan job router.

The only Phase 0 logic here is the P0001 handler: the DB trigger
enforce_domain_verified raises ERRCODE P0001 when a scan_jobs INSERT
references a domain whose verification_status != 'verified'.
We convert that into a clean 422 so callers get a meaningful error
instead of a raw 500.
"""
from typing import Annotated

import sqlalchemy.exc
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_session
from app.dependencies import get_current_user
from app.models.user import User

router = APIRouter(prefix="/scans", tags=["scans"])

AuthDep = Annotated[User, Depends(get_current_user)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_scan(
    current_user: AuthDep,
    session: SessionDep,
) -> dict:
    """
    Phase 1 placeholder. Full implementation adds:
      - CreateScanRequest body (domain_id, modules, config)
      - ScanJob insert
      - Job enqueue (BullMQ / Celery)
    """
    try:
        # Phase 1: session.add(ScanJob(...)) goes here
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Scanning is not yet available (Phase 1)",
        )
    except sqlalchemy.exc.DBAPIError as e:
        if getattr(e.orig, "pgcode", None) == "P0001":
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Domain not verified. Verify ownership before scanning.",
            )
        raise


@router.get("", status_code=status.HTTP_200_OK)
async def list_scans(
    current_user: AuthDep,
    session: SessionDep,
) -> dict:
    """Phase 1 placeholder."""
    return {"scans": []}


@router.get("/{scan_id}", status_code=status.HTTP_200_OK)
async def get_scan(
    scan_id: str,
    current_user: AuthDep,
    session: SessionDep,
) -> dict:
    """Phase 1 placeholder."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Scanning is not yet available (Phase 1)",
    )
