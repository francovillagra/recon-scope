import uuid
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, field_validator
import re

_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE,
)

VerificationStatus = Literal["pending", "verified", "failed"]
VerificationMethod = Literal["dns_txt", "well_known_file"]


class CreateDomainRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower()
        if not _DOMAIN_RE.match(v):
            raise ValueError("Invalid domain name (e.g. example.com)")
        return v


class VerifyDomainRequest(BaseModel):
    method: VerificationMethod = "dns_txt"


class DnsTxtInstructions(BaseModel):
    record_name: str
    record_type: str = "TXT"
    record_value: str


class WellKnownFileInstructions(BaseModel):
    url: str
    file_path: str
    content: str


class VerificationInstructions(BaseModel):
    domain: str
    token: str
    dns_txt: DnsTxtInstructions
    well_known_file: WellKnownFileInstructions


class DomainOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    user_id: uuid.UUID
    domain: str
    verification_status: VerificationStatus
    verification_method: VerificationMethod
    verification_token: str
    verified_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime


class DomainWithInstructions(BaseModel):
    domain: DomainOut
    instructions: VerificationInstructions


class DomainListResponse(BaseModel):
    domains: list[DomainOut]


class VerifyResponse(BaseModel):
    domain: DomainOut
    already_verified: bool = False
    error: Optional[str] = None
    instructions: Optional[VerificationInstructions] = None
