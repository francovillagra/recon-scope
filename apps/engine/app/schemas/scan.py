import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, field_validator

VALID_PORT_RANGES = {"top-100", "top-1000", "full"}


class CreateScanRequest(BaseModel):
    domain_id: uuid.UUID
    modules: list[str] = ["subdomains"]
    port_range: str = "top-1000"
    passive_only: bool = True
    timeout_seconds: int = 30

    @field_validator("port_range")
    @classmethod
    def validate_port_range(cls, v: str) -> str:
        if v not in VALID_PORT_RANGES:
            raise ValueError(f"port_range must be one of {sorted(VALID_PORT_RANGES)}")
        return v


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


class PortOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    host: str
    port: int
    protocol: str
    state: str
    service: Optional[str]
    banner: Optional[str]
    created_at: datetime


class ScanDetailResponse(BaseModel):
    job: ScanJobOut
    subdomains: list[SubdomainOut] = []
    ports: list[PortOut] = []
