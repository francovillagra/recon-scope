"""Registro y login: contraseñas, límite de intentos, bcrypt fuera del hilo principal, tokens y auditoría."""
import asyncio
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_engine
from app.models.audit_log import AuditLog
from app.routers import auth as auth_router
from app.services import auth_service
from app.services.auth_service import PasswordWorkBusy, hash_password_async, verify_password_async

pytestmark = [pytest.mark.db, pytest.mark.usefixtures("clean_db")]

PASSWORD = "correct horse battery"
REGISTER = "/api/v1/auth/register"
LOGIN = "/api/v1/auth/login"


async def _register(client, email="ana@example.com", password=PASSWORD, ip=None, tos=True):
    headers = {"X-Forwarded-For": ip} if ip else {}
    return await client.post(REGISTER, json={"email": email, "password": password, "tos_accepted": tos}, headers=headers)


async def _login(client, email="ana@example.com", password=PASSWORD, ip=None):
    headers = {"X-Forwarded-For": ip} if ip else {}
    return await client.post(LOGIN, json={"email": email, "password": password}, headers=headers)


@pytest.fixture
def behind_one_proxy(monkeypatch):
    """Como en Railway: la IP del cliente es la última del encabezado X-Forwarded-For."""
    monkeypatch.setattr(settings, "TRUSTED_PROXY_COUNT", 1)


# ── Lo básico, que no tenía pruebas ──────────────────────────────────────────────────────────────────────────────

async def test_register_then_login_gives_a_token_that_works(client):
    registered = await _register(client)
    assert registered.status_code == 201 and registered.json()["user"]["email"] == "ana@example.com"
    assert "password" not in registered.text

    logged = await _login(client, "ANA@example.com")  # el correo no distingue mayúsculas
    assert logged.status_code == 200
    me = await client.get("/api/v1/domains", headers={"Authorization": f"Bearer {logged.json()['token']}"})
    assert me.status_code == 200


async def test_wrong_password_and_unknown_user_look_the_same(client):
    await _register(client)
    wrong = await _login(client, password="not the password")
    unknown = await _login(client, "nadie@example.com")
    assert (wrong.status_code, wrong.json()) == (unknown.status_code, unknown.json()) == (401, {"detail": "Invalid credentials"})


def test_the_stand_in_hash_for_unknown_users_costs_as_much_as_a_real_one():
    """Si el costo fuera otro, el tiempo de respuesta delataría qué correos están registrados."""
    assert auth_service._DUMMY_HASH.startswith(f"$2b${settings.BCRYPT_ROUNDS:02d}$")
    assert auth_service.verify_password("otra cosa", None) is False
    assert auth_service.verify_password("password-for-timing-equalization", None) is True  # es un hash válido


async def test_duplicate_emails_and_missing_terms_are_refused(client):
    assert (await _register(client)).status_code == 201
    assert (await _register(client, "ANA@example.com")).status_code == 409
    assert (await _register(client, "otra@example.com", tos=False)).status_code == 422


# ── Contraseñas ──────────────────────────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "password",
    ["short", "1234567", "a" * 73, "ñ" * 37, "a" * 5000, "valid-but\x00-with-null-byte"],
    ids=["short", "seven", "73-bytes", "74-bytes-unicode", "5000-chars", "null-byte"],
)
async def test_register_refuses_passwords_bcrypt_cannot_handle_properly(client, password):
    assert (await _register(client, password=password)).status_code == 422


@pytest.mark.parametrize("password", ["a" * 8, "a" * 72, "ñ" * 36, "contraseña con espacios y 'comillas'"])
async def test_register_accepts_passwords_bcrypt_checks_in_full(client, password):
    assert (await _register(client, password=password)).status_code == 201
    assert (await _login(client, password=password)).status_code == 200


@pytest.mark.parametrize("password", ["a" * 129, "a" * 5000, "has\x00null"])
async def test_login_does_not_pass_absurd_passwords_to_bcrypt(client, password):
    """Antes una contraseña de más de 4096 caracteres daba 500."""
    res = await _login(client, password=password)
    assert res.status_code == 422


# ── Límite de intentos de login ──────────────────────────────────────────────────────────────────────────────────

async def test_eight_wrong_passwords_lock_the_account_for_that_address_even_with_the_right_one(client, behind_one_proxy):
    await _register(client, ip="203.0.113.1")
    codes = [(await _login(client, password=f"wrong {i}", ip="203.0.113.1")).status_code for i in range(8)]
    assert codes == [401] * 8

    locked = await _login(client, ip="203.0.113.1")  # ni con la contraseña correcta mientras dure el bloqueo
    assert locked.status_code == 429 and int(locked.headers["retry-after"]) > 0
    assert "Too many" in locked.json()["detail"]

    elsewhere = await _login(client, ip="198.51.100.9")  # otra dirección no queda bloqueada: nadie puede dejar afuera a otro
    assert elsewhere.status_code == 200


async def test_an_account_that_does_not_exist_locks_the_same_way_so_it_cannot_be_told_apart(client, behind_one_proxy):
    known, unknown = [], []
    await _register(client, ip="203.0.113.1")
    for email, bucket in (("ana@example.com", known), ("nadie@example.com", unknown)):
        for i in range(9):
            res = await _login(client, email, password=f"wrong {i}", ip="203.0.113.1")
            bucket.append((res.status_code, res.json()["detail"]))
    assert known == unknown
    assert known[:8] == [(401, "Invalid credentials")] * 8 and known[8][0] == 429


async def test_a_good_login_forgets_the_earlier_mistakes(client, behind_one_proxy):
    await _register(client, ip="203.0.113.1")
    for round_ in range(3):
        for i in range(7):
            assert (await _login(client, password=f"wrong {round_}-{i}", ip="203.0.113.1")).status_code == 401
        assert (await _login(client, ip="203.0.113.1")).status_code == 200  # una equivocación más y habría quedado bloqueada


async def test_one_address_trying_many_accounts_is_stopped_too(client, behind_one_proxy):
    codes = [(await _login(client, f"user{i}@example.com", password="x" * 10, ip="203.0.113.1")).status_code for i in range(31)]
    assert codes == [401] * 30 + [429]
    assert (await _login(client, "user99@example.com", ip="198.51.100.9")).status_code == 401  # otra dirección sigue igual


async def test_requests_turned_away_by_the_lock_do_not_use_up_the_address_budget(client, behind_one_proxy):
    """Una oficina detrás de una sola IP no se bloquea entera porque alguien insista contra una cuenta ya bloqueada."""
    for i in range(8):
        await _login(client, "ana@example.com", password=f"wrong {i}", ip="203.0.113.1")
    assert [(await _login(client, "ana@example.com", ip="203.0.113.1")).status_code for _ in range(40)] == [429] * 40
    assert (await _login(client, "otra@example.com", password="wrong", ip="203.0.113.1")).status_code == 401


async def test_successful_logins_do_not_use_up_the_address_budget(client, behind_one_proxy):
    await _register(client, ip="203.0.113.1")
    assert [(await _login(client, ip="203.0.113.1")).status_code for _ in range(40)] == [200] * 40
    assert (await _login(client, password="wrong", ip="203.0.113.1")).status_code == 401


async def test_parallel_guesses_cannot_get_around_the_limit(client, behind_one_proxy):
    """El cupo se reserva antes de calcular el hash: 40 intentos a la vez no son 40 intentos permitidos."""
    await _register(client, ip="203.0.113.1")
    results = await asyncio.gather(*[_login(client, password=f"wrong {i}", ip="203.0.113.1") for i in range(40)])
    codes = sorted(r.status_code for r in results)
    assert codes.count(401) == 8 and codes.count(429) == 32


async def test_an_ipv6_client_cannot_rotate_addresses_inside_its_network(client, behind_one_proxy):
    codes = [
        (await _login(client, f"user{i}@example.com", password="x" * 10, ip=f"2001:db8:aaaa:bbbb::{i + 1:x}")).status_code
        for i in range(31)
    ]
    assert codes == [401] * 30 + [429]


async def test_a_spoofed_forwarded_for_does_not_help_when_it_is_the_proxy_that_counts(client, behind_one_proxy):
    """El cliente escribe lo que quiera al principio de X-Forwarded-For; el proxy agrega su IP real al final."""
    codes = [
        (await _login(client, "ana@example.com", password=f"wrong {i}", ip=f"10.99.{i}.1, 203.0.113.1")).status_code
        for i in range(9)
    ]
    assert codes == [401] * 8 + [429]


async def test_sign_ups_are_limited_per_address(client, behind_one_proxy):
    codes = [(await _register(client, f"user{i}@example.com", ip="203.0.113.1")).status_code for i in range(11)]
    assert codes == [201] * 10 + [429]
    assert (await _register(client, "otra@example.com", ip="198.51.100.9")).status_code == 201


# ── bcrypt no frena al resto del motor ───────────────────────────────────────────────────────────────────────────

def _slow_function(seconds: float, calls: list | None = None):
    def work(*args):
        if calls is not None:
            calls.append(args)
        time.sleep(seconds)  # bloquea el hilo que lo ejecuta, como un bcrypt de costo alto
        return "hash"

    return work


async def _longest_pause_while(coro, tick: float = 0.01) -> float:
    """Cuánto tardó, como máximo, el bucle de eventos en volver a atender mientras `coro` se ejecutaba."""
    longest = 0.0
    done = asyncio.Event()
    running = asyncio.Event()

    async def ticker():
        nonlocal longest
        last = time.perf_counter()
        running.set()
        while not done.is_set():
            await asyncio.sleep(tick)
            now = time.perf_counter()
            longest = max(longest, now - last - tick)
            last = now

    task = asyncio.create_task(ticker())
    await running.wait()  # el reloj tiene que estar andando ANTES de empezar el trabajo, si no no mide nada
    await asyncio.sleep(0.05)
    try:
        await coro
    finally:
        done.set()
        await task
    return longest


async def test_hashing_a_password_does_not_block_the_event_loop(monkeypatch):
    monkeypatch.setattr(auth_service, "hash_password", _slow_function(0.4))
    monkeypatch.setattr(auth_service, "_executor", None)
    pause = await _longest_pause_while(hash_password_async("whatever-password"))
    assert pause < 0.15, f"el bucle de eventos estuvo {pause:.2f}s sin atender"


async def test_verifying_a_password_does_not_block_the_event_loop(monkeypatch):
    monkeypatch.setattr(auth_service, "verify_password", lambda plain, hashed: time.sleep(0.4) or True)
    monkeypatch.setattr(auth_service, "_executor", None)
    assert await _longest_pause_while(verify_password_async("x", "y")) < 0.15


async def test_the_health_check_keeps_answering_while_logins_are_being_checked(client, monkeypatch):
    await _register(client)
    monkeypatch.setattr(auth_service, "verify_password", lambda plain, hashed: time.sleep(0.4) or False)
    monkeypatch.setattr(auth_service, "_executor", None)

    async def health_latency():
        # Se mide desde que se pidió despertar, no desde que despertó: si el bucle estuvo bloqueado, la demora
        # ocurre antes de que este código vuelva a correr.
        asked = time.perf_counter()
        await asyncio.sleep(0.05)
        assert (await client.get("/api/v1/health")).status_code == 200
        return time.perf_counter() - asked - 0.05

    results = await asyncio.gather(*[_login(client, password=f"wrong {i}") for i in range(4)], health_latency())
    assert results[-1] < 0.2, f"/health tardó {results[-1]:.2f}s con logins en curso"
    assert [r.status_code for r in results[:-1]] == [401] * 4


async def test_only_a_few_passwords_are_hashed_at_once(monkeypatch):
    monkeypatch.setattr(settings, "BCRYPT_CONCURRENCY", 2)
    monkeypatch.setattr(auth_service, "_executor", None)
    running = peak = 0
    lock = threading.Lock()

    def work(*_):
        nonlocal running, peak
        with lock:
            running += 1
            peak = max(peak, running)
        time.sleep(0.05)
        with lock:
            running -= 1
        return "hash"

    monkeypatch.setattr(auth_service, "hash_password", work)
    await asyncio.gather(*[hash_password_async("x" * 10) for _ in range(8)])
    assert peak == 2


async def test_when_too_many_are_waiting_new_ones_are_refused_instead_of_piling_up(monkeypatch):
    monkeypatch.setattr(settings, "BCRYPT_CONCURRENCY", 1)
    monkeypatch.setattr(settings, "BCRYPT_MAX_PENDING", 3)
    monkeypatch.setattr(auth_service, "_executor", None)
    monkeypatch.setattr(auth_service, "hash_password", _slow_function(0.1))

    results = await asyncio.gather(*[hash_password_async("x" * 10) for _ in range(6)], return_exceptions=True)
    assert results[:3] == ["hash"] * 3
    assert all(isinstance(r, PasswordWorkBusy) for r in results[3:])
    assert auth_service._pending == 0  # nada quedó contado de más
    assert await hash_password_async("x" * 10) == "hash"  # y se recupera


async def test_a_busy_engine_answers_503_and_gives_the_attempt_back(client, behind_one_proxy, monkeypatch):
    await _register(client, ip="203.0.113.1")
    monkeypatch.setattr(settings, "BCRYPT_CONCURRENCY", 1)
    monkeypatch.setattr(settings, "BCRYPT_MAX_PENDING", 1)
    monkeypatch.setattr(auth_service, "_executor", None)
    monkeypatch.setattr(auth_service, "verify_password", lambda plain, hashed: time.sleep(0.3) or False)

    results = await asyncio.gather(*[_login(client, password=f"wrong {i}", ip="203.0.113.1") for i in range(4)])
    codes = sorted(r.status_code for r in results)
    assert codes == [401, 503, 503, 503]
    assert all(r.headers.get("retry-after") == "5" for r in results if r.status_code == 503)

    monkeypatch.undo()  # bcrypt normal otra vez
    # Los rechazados por ocupación no gastaron intentos: de los 8 permitidos quedó usado uno solo.
    monkeypatch.setattr(settings, "TRUSTED_PROXY_COUNT", 1)
    codes = [(await _login(client, password=f"wrong again {i}", ip="203.0.113.1")).status_code for i in range(8)]
    assert codes == [401] * 7 + [429]


async def test_registering_while_the_engine_is_busy_answers_503(client, monkeypatch):
    monkeypatch.setattr(settings, "BCRYPT_MAX_PENDING", 1)
    monkeypatch.setattr(auth_service, "_pending", 1)  # ya hay un trabajo en curso
    res = await _register(client)
    assert res.status_code == 503 and res.headers["retry-after"] == "5"


# ── Tokens ───────────────────────────────────────────────────────────────────────────────────────────────────────

def _forge(secret: str = None, **claims) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": str(uuid.uuid4()), "iat": now, "exp": now + timedelta(days=1), **claims}
    payload = {k: v for k, v in payload.items() if v is not None}
    return jwt.encode(payload, secret or settings.JWT_SECRET, algorithm="HS256")


async def test_only_complete_tokens_signed_with_our_secret_are_accepted(client):
    user_id = (await _register(client)).json()["user"]["id"]
    ok = _forge(sub=user_id)
    expired = _forge(sub=user_id, exp=datetime.now(timezone.utc) - timedelta(seconds=5))
    no_expiry = jwt.encode({"sub": user_id, "iat": datetime.now(timezone.utc)}, settings.JWT_SECRET, algorithm="HS256")
    wrong_secret = _forge("another-secret-that-is-long-enough-1234567890", sub=user_id)
    unsigned = jwt.encode({"sub": user_id, "exp": datetime.now(timezone.utc) + timedelta(days=1)}, None, algorithm="none")

    status = {}
    for name, token in {"ok": ok, "expired": expired, "no_expiry": no_expiry, "wrong_secret": wrong_secret, "unsigned": unsigned}.items():
        status[name] = (await client.get("/api/v1/domains", headers={"Authorization": f"Bearer {token}"})).status_code
    assert status == {"ok": 200, "expired": 401, "no_expiry": 401, "wrong_secret": 401, "unsigned": 401}


# ── Auditoría ────────────────────────────────────────────────────────────────────────────────────────────────────

async def _audit_ip_after_registering_a_domain(client, **headers) -> str | None:
    token = (await _register(client)).json()["token"]
    res = await client.post("/api/v1/domains", json={"domain": "example.com"}, headers={"Authorization": f"Bearer {token}", **headers})
    assert res.status_code == 201
    async with AsyncSession(get_engine()) as s:
        row = (await s.scalars(select(AuditLog).where(AuditLog.action == "domain_registered"))).one()
        return str(row.ip_address) if row.ip_address else None


async def test_the_audit_log_records_the_real_client_behind_a_trusted_proxy(client, behind_one_proxy):
    assert await _audit_ip_after_registering_a_domain(client, **{"X-Forwarded-For": "6.6.6.6, 203.0.113.5"}) == "203.0.113.5"


async def test_the_audit_log_ignores_forwarded_for_when_no_proxy_is_trusted(client):
    assert await _audit_ip_after_registering_a_domain(client, **{"X-Forwarded-For": "6.6.6.6"}) == "127.0.0.1"
