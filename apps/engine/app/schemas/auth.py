import uuid
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

# bcrypt solo usa los primeros 72 bytes: una contraseña más larga se aceptaría "completa" pero se comprobaría
# truncada. Mejor rechazarla que dejar creer que los caracteres de más protegen algo.
MAX_PASSWORD_BYTES = 72
# Tope para el login: un valor enorme no tiene por qué llegar al hash (y las cuentas existentes ya cumplen esto).
MAX_LOGIN_PASSWORD_CHARS = 128


def _reject_nul(value: str) -> str:
    # Un carácter nulo hace fallar el hash de passlib con un error interno (500).
    if "\x00" in value:
        raise ValueError("Password cannot contain null characters")
    return value


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    tos_accepted: bool

    @field_validator("password")
    @classmethod
    def password_rules(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if len(v.encode("utf-8")) > MAX_PASSWORD_BYTES:
            raise ValueError(f"Password must be at most {MAX_PASSWORD_BYTES} bytes")
        return _reject_nul(v)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(max_length=MAX_LOGIN_PASSWORD_CHARS)

    @field_validator("password")
    @classmethod
    def password_has_no_nul(cls, v: str) -> str:
        return _reject_nul(v)


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
