import asyncio
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Callable, TypeVar

import jwt
from passlib.context import CryptContext

from app.config import settings

# CryptContext auto-selects rounds from settings at hash time
_pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=settings.BCRYPT_ROUNDS,
)

# Hash de una contraseña cualquiera, calculado con el costo vigente: comprobar contra él tarda lo mismo que contra
# un usuario real, aunque se cambie BCRYPT_ROUNDS. (Antes era un texto fijo con costo 12: con otro costo configurado
# el login de un correo inexistente tardaba distinto y delataba qué correos están registrados.)
_DUMMY_HASH = _pwd_context.hash("password-for-timing-equalization")


def hash_password(password: str) -> str:
    return _pwd_context.hash(password)


def verify_password(plain: str, hashed: str | None) -> bool:
    """Always runs bcrypt even when hashed is None to prevent timing attacks."""
    return _pwd_context.verify(plain, hashed or _DUMMY_HASH)


# ── bcrypt fuera del hilo principal ──────────────────────────────────────────────────────────────────────────────
# Un hash de bcrypt tarda ~250 ms de CPU. Si corre en el hilo del servidor, mientras tanto el motor no atiende nada
# más (ni siquiera /health): bastaba con mandar logins en paralelo para dejar el servicio sin respuesta. Por eso corre
# en hilos propios (bcrypt suelta el GIL), con un tope de trabajos simultáneos y un tope de pedidos esperando.

T = TypeVar("T")


class PasswordWorkBusy(Exception):
    """Hay demasiados trabajos de contraseña esperando: se rechaza el pedido en vez de acumularlo."""


_executor: ThreadPoolExecutor | None = None
_pending = 0


def _pool() -> ThreadPoolExecutor:
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(max_workers=settings.BCRYPT_CONCURRENCY, thread_name_prefix="bcrypt")
    return _executor


async def _off_the_loop(func: Callable[..., T], *args: object) -> T:
    global _pending
    if _pending >= settings.BCRYPT_MAX_PENDING:
        raise PasswordWorkBusy()
    _pending += 1
    try:
        return await asyncio.get_running_loop().run_in_executor(_pool(), func, *args)
    finally:
        _pending -= 1


async def hash_password_async(password: str) -> str:
    return await _off_the_loop(hash_password, password)


async def verify_password_async(plain: str, hashed: str | None) -> bool:
    return await _off_the_loop(verify_password, plain, hashed)


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
        options={"require": ["exp", "iat", "sub"]},  # un token sin vencimiento no vale
    )
