"""Cabeceras, tope de cuerpo, CORS, documentación pública, IP del cliente y secreto JWT. Sin base de datos."""
import logging
import re
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, Request
from pydantic import ValidationError

from app import security
from app.config import Settings, settings
from app.main import create_app
from app.security import BodyLimitMiddleware, client_ip, rate_limit_key

ORIGIN = "https://app.example"
SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "strict-transport-security": "max-age=31536000",
}


def _client(app: FastAPI, **kwargs) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, **kwargs), base_url="http://test")


@pytest.fixture
def app(monkeypatch) -> FastAPI:
    monkeypatch.setattr(settings, "CORS_ORIGINS", [ORIGIN])
    return create_app()


def _assert_security_headers(res: httpx.Response) -> None:
    for name, value in SECURITY_HEADERS.items():
        assert res.headers.get(name) == value, f"falta {name} en {res.status_code}"


# ── Cabeceras de seguridad ───────────────────────────────────────────────────────────────────────────────────────

async def test_every_kind_of_response_carries_the_security_headers(app):
    @app.get("/boom")
    async def boom():
        raise RuntimeError("fallo interno con datos sensibles")

    async with _client(app, raise_app_exceptions=False) as c:
        responses = {
            "200": await c.get("/api/v1/health"),
            "404": await c.get("/api/v1/no-existe"),
            "401": await c.get("/api/v1/domains"),
            "422": await c.post("/api/v1/auth/login", json={}),
            "405": await c.put("/api/v1/health"),
            "500": await c.get("/boom"),
        }
    assert {k: r.status_code for k, r in responses.items()} == {"200": 200, "404": 404, "401": 401, "422": 422, "405": 405, "500": 500}
    for res in responses.values():
        _assert_security_headers(res)
    assert responses["500"].json() == {"detail": "Internal server error"}  # sin detalles del fallo


async def test_a_handler_can_still_set_its_own_cache_control(app):
    @app.get("/cacheable")
    async def cacheable():
        from fastapi.responses import JSONResponse

        return JSONResponse({"ok": True}, headers={"Cache-Control": "public, max-age=60"})

    async with _client(app) as c:
        res = await c.get("/cacheable")
    assert res.headers["cache-control"] == "public, max-age=60"
    assert res.headers["x-content-type-options"] == "nosniff"


async def test_validation_errors_do_not_repeat_what_the_client_sent(app):
    secret = "my-very-secret-" + "x" * 150  # demasiado larga para el login
    async with _client(app) as c:
        res = await c.post("/api/v1/auth/login", json={"email": "ana@example.com", "password": secret})
        bad_email = await c.post("/api/v1/auth/login", json={"email": "not-an-email", "password": "x"})
    for response in (res, bad_email):
        assert response.status_code == 422
        assert all(set(e) == {"type", "loc", "msg"} for e in response.json()["detail"])
    assert secret not in res.text and "my-very-secret" not in res.text
    assert res.json()["detail"][0]["loc"] == ["body", "password"]


# ── Documentación de la API ──────────────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", ["/openapi.json", "/docs", "/redoc"])
async def test_the_api_description_is_not_public_in_production(app, path):
    async with _client(app) as c:
        assert (await c.get(path)).status_code == 404


async def test_the_api_description_is_available_while_developing(monkeypatch):
    monkeypatch.setattr(settings, "DEBUG", True)
    async with _client(create_app()) as c:
        assert (await c.get("/openapi.json")).status_code == 200
        assert (await c.get("/docs")).status_code == 200


# ── CORS ─────────────────────────────────────────────────────────────────────────────────────────────────────────

def _preflight(origin: str, method: str = "POST", headers: str = "authorization,content-type") -> dict:
    return {"Origin": origin, "Access-Control-Request-Method": method, "Access-Control-Request-Headers": headers}


async def test_cors_preflight_is_limited_to_the_configured_origin_and_to_what_the_web_uses(app):
    async with _client(app) as c:
        ok = await c.options("/api/v1/scans", headers=_preflight(ORIGIN))
        assert ok.status_code == 200
        assert ok.headers["access-control-allow-origin"] == ORIGIN
        assert "access-control-allow-credentials" not in ok.headers  # la sesión viaja en Authorization, no en cookies
        allowed = {m.strip() for m in ok.headers["access-control-allow-methods"].split(",")}
        assert allowed == {"GET", "POST", "DELETE", "OPTIONS"}
        # Starlette siempre suma los encabezados "seguros" de CORS; lo que importa es que no sea un comodín.
        allowed_headers = {h.strip().lower() for h in ok.headers["access-control-allow-headers"].split(",")}
        assert {"authorization", "content-type"} <= allowed_headers
        assert allowed_headers <= {"authorization", "content-type", "accept", "accept-language", "content-language"}

        evil = await c.options("/api/v1/scans", headers=_preflight("https://evil.example"))
        assert evil.status_code == 400 and "access-control-allow-origin" not in evil.headers

        for method in ("PUT", "PATCH"):
            assert (await c.options("/api/v1/scans", headers=_preflight(ORIGIN, method=method))).status_code == 400
        assert (await c.options("/api/v1/scans", headers=_preflight(ORIGIN, headers="x-evil"))).status_code == 400


async def test_cors_headers_reach_error_responses_and_expose_retry_after(app):
    async with _client(app) as c:
        res = await c.post("/api/v1/auth/login", json={}, headers={"Origin": ORIGIN})
        too_big = await c.post(
            "/api/v1/auth/login", content=b"x" * (settings.MAX_REQUEST_BYTES + 1),
            headers={"Origin": ORIGIN, "Content-Type": "application/json"},
        )
        other_origin = await c.post("/api/v1/auth/login", json={}, headers={"Origin": "https://evil.example"})
    assert res.status_code == 422 and res.headers["access-control-allow-origin"] == ORIGIN
    assert "retry-after" in res.headers.get("access-control-expose-headers", "").lower()
    # Si el cuerpo es demasiado grande el navegador igual puede leer el 413 (CORS está afuera del tope).
    assert too_big.status_code == 413 and too_big.headers["access-control-allow-origin"] == ORIGIN
    assert "access-control-allow-origin" not in other_origin.headers


# ── Tope del cuerpo ──────────────────────────────────────────────────────────────────────────────────────────────

def _echo_app(max_bytes: int) -> FastAPI:
    echo = FastAPI()
    echo.add_middleware(BodyLimitMiddleware, max_bytes=max_bytes)

    @echo.post("/echo")
    async def handler(request: Request):
        return {"size": len(await request.body())}

    return echo


async def test_a_body_exactly_at_the_limit_passes_and_one_byte_more_does_not():
    async with _client(_echo_app(100)) as c:
        assert (await c.post("/echo", content=b"x" * 100)).json() == {"size": 100}
        res = await c.post("/echo", content=b"x" * 101)
    assert res.status_code == 413 and res.json() == {"detail": "Request body too large"}


async def test_a_declared_size_over_the_limit_is_refused_without_reading_the_body():
    reads = 0

    async def receive():
        nonlocal reads
        reads += 1
        return {"type": "http.request", "body": b"x" * 10, "more_body": True}

    sent: list[dict] = []

    async def send(message):
        sent.append(message)

    async def never(scope, receive, send):
        raise AssertionError("la petición no tendría que llegar a la aplicación")

    scope = {
        "type": "http", "method": "POST", "path": "/x", "query_string": b"", "client": ("127.0.0.1", 1),
        "headers": [(b"content-length", b"5000000000")],
    }
    await BodyLimitMiddleware(never, max_bytes=1000)(scope, receive, send)

    assert reads == 0
    assert sent[0]["status"] == 413


@pytest.mark.parametrize("declared", ["abc", "-5", "1e3", ""])
async def test_a_content_length_that_is_not_a_number_is_a_bad_request(declared):
    async def never(scope, receive, send):
        raise AssertionError("no tendría que llegar a la aplicación")

    sent: list[dict] = []

    async def send(message):
        sent.append(message)

    async def receive():
        raise AssertionError("no se lee el cuerpo")

    scope = {"type": "http", "method": "POST", "path": "/x", "query_string": b"", "headers": [(b"content-length", declared.encode())]}
    await BodyLimitMiddleware(never, max_bytes=1000)(scope, receive, send)
    assert sent[0]["status"] == 400


async def test_a_body_that_arrives_in_chunks_without_a_declared_size_is_cut_when_it_goes_over():
    consumed = 0

    async def chunks():
        nonlocal consumed
        for _ in range(1000):  # 100 MB si se leyera todo
            consumed += 1
            yield b"x" * 100_000

    async with _client(_echo_app(250_000)) as c:
        res = await c.post("/echo", content=chunks())

    assert res.status_code == 413
    assert consumed <= 4, f"se siguieron leyendo partes después del límite ({consumed})"


async def test_the_real_app_refuses_big_bodies_on_its_endpoints(app):
    async def chunks():
        for _ in range(30):
            yield b"x" * 100_000

    async with _client(app) as c:
        declared = await c.post("/api/v1/auth/register", content=b"x" * 1_500_000, headers={"Content-Type": "application/json"})
        streamed = await c.post("/api/v1/auth/login", content=chunks(), headers={"Content-Type": "application/json"})
    assert declared.status_code == 413 and streamed.status_code == 413
    _assert_security_headers(declared)


# ── IP del cliente ───────────────────────────────────────────────────────────────────────────────────────────────

def _request(peer: str | None = "10.0.0.9", forwarded: str | None = None) -> Request:
    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded is not None else []
    scope = {"type": "http", "method": "GET", "path": "/", "query_string": b"", "headers": headers,
             "client": (peer, 5555) if peer is not None else None}
    return Request(scope)


@pytest.mark.parametrize(
    "proxies, peer, forwarded, expected",
    [
        (0, "10.0.0.9", "1.2.3.4", "10.0.0.9"),  # sin proxies de confianza el encabezado no se lee
        (0, "10.0.0.9", None, "10.0.0.9"),
        (1, "10.0.0.9", "1.2.3.4", "1.2.3.4"),
        (1, "10.0.0.9", "6.6.6.6, 1.2.3.4", "1.2.3.4"),  # lo que escribió el cliente al principio no cuenta
        (1, "10.0.0.9", "6.6.6.6,   5.5.5.5 ,1.2.3.4", "1.2.3.4"),
        (1, "10.0.0.9", None, "10.0.0.9"),
        (1, "10.0.0.9", "", "10.0.0.9"),
        (1, "10.0.0.9", "1.2.3.4, no-es-una-ip", "10.0.0.9"),  # basura: se queda con la IP del socket
        (2, "10.0.0.9", "9.9.9.9, 1.2.3.4, 10.1.1.1", "1.2.3.4"),
        (2, "10.0.0.9", "1.2.3.4", "10.0.0.9"),  # menos eslabones que proxies: no se puede confiar
        (1, "10.0.0.9", "2001:DB8::1", "2001:db8::1"),
        (0, "2001:DB8::7", None, "2001:db8::7"),
        (1, None, "1.2.3.4", "1.2.3.4"),
        (0, None, "1.2.3.4", None),
        (0, "testclient", None, None),  # el "cliente" de algunas herramientas no es una IP
    ],
)
def test_client_ip_only_trusts_what_our_own_proxies_wrote(monkeypatch, proxies, peer, forwarded, expected):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_COUNT", proxies)
    assert client_ip(_request(peer, forwarded)) == expected


def test_a_spoofed_header_does_not_change_the_rate_limit_key(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_COUNT", 1)
    keys = {rate_limit_key(_request(forwarded=f"{fake}, 1.2.3.4")) for fake in ("8.8.8.8", "9.9.9.9", "7.7.7.7")}
    assert keys == {"1.2.3.4"}


def test_ipv6_clients_are_counted_by_their_64_prefix(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_COUNT", 0)
    same_network = {rate_limit_key(_request(a)) for a in ("2001:db8:1:2::1", "2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:DB8:1:2:ffff::")}
    assert same_network == {"2001:db8:1:2::/64"}
    assert rate_limit_key(_request("2001:db8:1:3::1")) == "2001:db8:1:3::/64"
    assert rate_limit_key(_request("203.0.113.7")) == "203.0.113.7"
    assert rate_limit_key(_request(None)) == "unknown"


def test_it_warns_once_when_a_proxy_header_arrives_but_no_proxy_is_trusted(monkeypatch, caplog):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_COUNT", 0)
    monkeypatch.setattr(security, "_warned_forwarded", False)
    with caplog.at_level(logging.WARNING, logger="app.security"):
        client_ip(_request(forwarded="1.2.3.4"))
        client_ip(_request(forwarded="1.2.3.4"))
    warnings = [r for r in caplog.records if "TRUSTED_PROXY_COUNT" in r.getMessage()]
    assert len(warnings) == 1


# ── Secreto JWT y valores de configuración ───────────────────────────────────────────────────────────────────────

def _settings(**overrides) -> Settings:
    base = {"DATABASE_URL": "postgresql+asyncpg://u@localhost/db", "JWT_SECRET": "k3Jx9vQw7LmP2sRt5YbN8cZd4HfG6aUe"}
    return Settings(_env_file=None, **{**base, **overrides})


@pytest.mark.parametrize(
    "secret",
    [
        "",
        "change-me-in-production",
        "short-secret",
        "a" * 31,
        "a" * 64,  # largo pero repetitivo
        "abab" * 16,
        "your-super-secret-jwt-token-with-at-least-32-characters-long",  # el ejemplo de muchos tutoriales
        "ChangeMe-" + "q7Zx" * 8,
        "this-is-just-an-example-value-0123456789abcdef",
    ],
)
def test_weak_or_example_jwt_secrets_are_refused(secret):
    with pytest.raises(ValidationError) as err:
        _settings(JWT_SECRET=secret)
    assert "JWT_SECRET" in str(err.value)


@pytest.mark.parametrize("secret", ["0123456789abcdef0123456789abcdef", "k3Jx9vQw7LmP2sRt5YbN8cZd4HfG6aUe", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"])
def test_strong_jwt_secrets_are_accepted(secret):
    assert _settings(JWT_SECRET=secret).JWT_SECRET == secret


def test_the_example_env_file_cannot_be_used_as_is(monkeypatch):
    example = Path(__file__).resolve().parents[3] / ".env.example"
    assert re.search(r"^JWT_SECRET=\s*$", example.read_text(), re.MULTILINE), "el ejemplo no debe traer un secreto"
    monkeypatch.delenv("JWT_SECRET", raising=False)
    with pytest.raises(ValidationError) as err:
        Settings(_env_file=example)
    assert "JWT_SECRET" in str(err.value)


def test_the_token_algorithm_cannot_be_set_to_something_unsafe():
    with pytest.raises(ValidationError):
        _settings(JWT_SECRET="k3Jx9vQw7LmP2sRt5YbN8cZd4HfG6aUe", JWT_ALGORITHM="none")
