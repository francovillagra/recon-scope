import uuid
from datetime import datetime, timedelta, timezone

import jwt
from passlib.context import CryptContext

from app.config import settings

# CryptContext auto-selects rounds from settings at hash time
_pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=settings.BCRYPT_ROUNDS,
)

# Dummy hash for constant-time comparison when the user doesn't exist
_DUMMY_HASH = "$2b$12$invalidhashfortimingprotectionXXXXXXXXXXXXXXXXXXXXXXX"


def hash_password(password: str) -> str:
    return _pwd_context.hash(password)


def verify_password(plain: str, hashed: str | None) -> bool:
    """Always runs bcrypt even when hashed is None to prevent timing attacks."""
    return _pwd_context.verify(plain, hashed or _DUMMY_HASH)


def create_access_token(user_id: uuid.UUID, email: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "iat": now,
        "exp": now + timedelta(days=settings.JWT_EXPIRES_DAYS),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Raises jwt.PyJWTError on invalid / expired tokens."""
    return jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
    )
