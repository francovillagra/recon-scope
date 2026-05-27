import uuid
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, EmailStr, field_validator


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    tos_accepted: bool

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    email: str
    role: Literal["user", "admin"]
    tos_accepted_at: Optional[datetime]
    created_at: datetime


class AuthResponse(BaseModel):
    token: str
    user: UserOut
