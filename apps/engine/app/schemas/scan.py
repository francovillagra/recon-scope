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


class HttpFingerprintOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    url: str
    status_code: Optional[int]
    server_header: Optional[str]
    title: Optional[str]
    # response_headers intentionally omitted — too large for list responses
    created_at: datetime


class TechnologyOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    name: str
    category: Optional[str]
    version: Optional[str]
    confidence: Optional[int]
    created_at: datetime


class TlsCertificateOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    host: str
    issuer: Optional[str]
    subject: Optional[str]
    valid_from: Optional[datetime]
    valid_to: Optional[datetime]
    is_valid: Optional[bool]
    signature_algorithm: Optional[str]
    san: list
    created_at: datetime


class FindingOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    category: str
    severity: str
    title: str
    description: Optional[str]
    evidence: dict
    created_at: datetime


class ScanDetailResponse(BaseModel):
    job: ScanJobOut
    subdomains: list[SubdomainOut] = []
    ports: list[PortOut] = []
    http_fingerprints: list[HttpFingerprintOut] = []
    technologies: list[TechnologyOut] = []
    tls_certificates: list[TlsCertificateOut] = []
    findings: list[FindingOut] = []
