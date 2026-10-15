import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_session
from app.models.user import User
from app.ratelimit import SlidingWindowLimiter
from app.schemas.auth import AuthResponse, LoginRequest, RegisterRequest, UserOut
from app.security import rate_limit_key
from app.services.auth_service import (
    PasswordWorkBusy,
    create_access_token,
    hash_password_async,
    verify_password_async,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Cada intento de login cuesta un bcrypt y puede ser una adivinanza de contraseña. El cupo se reserva ANTES de
# calcular el hash (así los pedidos en paralelo tampoco lo esquivan) y se devuelve si el login resulta correcto:
# lo que se cuenta son los fallos. Se limita por dirección y por dirección + cuenta; no por cuenta sola, porque
# entonces cualquiera podría bloquear la cuenta de otra persona desde su propia dirección.
_login_ip_limiter = SlidingWindowLimiter(limit=30, window_seconds=900)
_login_account_limiter = SlidingWindowLimiter(limit=8, window_seconds=900)
# Registrarse también cuesta un bcrypt y deja filas en la base.
_register_limiter = SlidingWindowLimiter(limit=10, window_seconds=3600)


def _too_many(detail: str, wait: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=detail, headers={"Retry-After": str(wait)}
    )


def _busy() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="The server is busy. Try again in a few seconds.",
        headers={"Retry-After": "5"},
    )


@router.post(
    "/register",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    body: RegisterRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> AuthResponse:
    if not body.tos_accepted:
        raise HTTPException(
            status_code=422,
            detail="Must accept Terms of Service",
        )

    wait = _register_limiter.hit(rate_limit_key(request))
    if wait is not None:
        raise _too_many("Too many sign-ups from this address. Try again later.", wait)

    email = body.email.lower()
    existing = await session.scalar(select(User).where(User.email == email))
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    try:
        password_hash = await hash_password_async(body.password)
    except PasswordWorkBusy:
        raise _busy()

    user = User(
        email=email,
        password_hash=password_hash,
        tos_accepted_at=datetime.now(timezone.utc),
    )
    session.add(user)
    try:
        await session.commit()
        await session.refresh(user)
    except IntegrityError:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    token = create_access_token(user.id, user.email, user.role)
    return AuthResponse(token=token, user=UserOut.model_validate(user))


@router.post("/login", response_model=AuthResponse)
async def login(
    body: LoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> AuthResponse:
    email = body.email.lower()
    ip_key = rate_limit_key(request)
    account_key = f"{ip_key}|{email}"

    # Antes de tocar la base o calcular nada: un cliente bloqueado no gasta CPU. Los pedidos rechazados acá no
    # cuentan como fallos (no probaron ninguna contraseña), así una oficina detrás de una misma IP no se bloquea
    # entera por insistir contra una cuenta ya bloqueada.
    wait = _login_ip_limiter.hit(ip_key)
    if wait is not None:
        raise _too_many("Too many failed login attempts. Try again later.", wait)
    wait = _login_account_limiter.hit(account_key)
    if wait is not None:
        _login_ip_limiter.refund(ip_key)
        raise _too_many("Too many failed login attempts. Try again later.", wait)

    valid = False
    evaluated = False
    try:
        user = await session.scalar(select(User).where(User.email == email))
        # Corre bcrypt incluso si el usuario no existe: la respuesta tarda lo mismo.
        valid = await verify_password_async(body.password, user.password_hash if user else None)
        evaluated = True
    except PasswordWorkBusy:
        raise _busy()
    finally:
        if not evaluated:  # no se llegó a probar la contraseña: se devuelve el cupo
            _login_ip_limiter.refund(ip_key)
            _login_account_limiter.refund(account_key)

    if not valid:
        if _login_account_limiter.retry_after(account_key) is not None:
            logger.warning("Login bloqueado por demasiados fallos desde %s", ip_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    _login_ip_limiter.refund(ip_key)
    _login_account_limiter.clear(account_key)
    token = create_access_token(user.id, user.email, user.role)  # type: ignore[union-attr]
    return AuthResponse(token=token, user=UserOut.model_validate(user))
