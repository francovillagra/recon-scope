import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class CreateScanRequest(BaseModel):
    domain_id: uuid.UUID
    modules: list[str] = ["subdomains"]


class CreateScanResponse(BaseModel):
    job_id: uuid.UUID
    status: str  # always "queued" on creation


class ScanJobOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    domain_id: uuid.UUID
    user_id: uuid.UUID
    target: str
    status: str
    progress: int
    config: dict
    error_message: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime


class SubdomainOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    hostname: str
    source: str
    resolved_ip: Optional[str]
    created_at: datetime


class ScanDetailResponse(BaseModel):
    job: ScanJobOut
    subdomains: list[SubdomainOut] = []
