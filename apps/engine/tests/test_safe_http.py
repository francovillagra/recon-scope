"""El cliente HTTP del motor: no se conecta a direcciones internas, no se sale del dominio verificado y no
se deja arrastrar por el DNS ni por las redirecciones."""
import asyncio

import httpx
import pytest

from app.config import settings
from app.recon import safe_http
from app.recon.netguard import BlockedTarget
from app.recon.safe_http import GuardedBackend, fetch_in_scope, guarded_transport

from .netfakes import LocalServer, FakeBackend, OK_RESPONSE, fake_dns, redirect_response

PUBLIC_IP = "93.184.216.34"


# ── La guarda funciona de verdad: conexiones reales a un servicio local ──────────────────────────────────────────

async def test_a_name_pointing_to_loopback_is_never_connected(monkeypatch):
    fake_dns(monkeypatch, {"evil.test": ["127.0.0.1"]})
    async with LocalServer() as internal:
        with pytest.raises(BlockedTarget):
            await fetch_in_scope(f"http://evil.test:{internal.port}/admin", scope="evil.test", timeout=3)
        assert internal.connections == 0  # ni siquiera se abrió el socket


async def test_an_ip_literal_url_is_blocked_too():
    async with LocalServer() as internal:
        with pytest.raises(BlockedTarget):
            await fetch_in_scope(f"http://127.0.0.1:{internal.port}/", scope="127.0.0.1", timeout=3)
        assert internal.connections == 0


async def test_with_the_flag_on_the_same_request_goes_through(monkeypatch):
    """Control del experimento: si la prueba anterior pasa por la guarda y no por otra razón, con la guarda apagada conecta."""
    fake_dns(monkeypatch, {"evil.test": ["127.0.0.1"]})
    monkeypatch.setattr(settings, "ALLOW_PRIVATE_TARGETS", True)
    async with LocalServer() as internal:
        fetched = await fetch_in_scope(f"http://evil.test:{internal.port}/", scope="evil.test", timeout=3)
        assert fetched.status_code == 200
        assert internal.connections == 1
        assert b"Host: evil.test" in internal.requests[0]  # el nombre sigue siendo el de la URL


async def test_dns_rebinding_the_validated_address_is_the_one_used(monkeypatch):
    """Un DNS que contesta una dirección pública la primera vez y 127.0.0.1 la segunda no cambia el destino:
    el nombre se resuelve una sola vez y la conexión va a la dirección validada."""
    answers = iter([[PUBLIC_IP], ["127.0.0.1"], ["127.0.0.1"]])
    lookups: list[str] = []

    async def rebinding_lookup(host, port):
        lookups.append(host)
        return next(answers)

    from app.recon import netguard

    monkeypatch.setattr(netguard, "_lookup", rebinding_lookup)
    backend = FakeBackend()
    fetched = await fetch_in_scope(
        "http://rebind.test/", scope="rebind.test", timeout=3, transport=guarded_transport(backend=backend)
    )

    assert fetched.status_code == 200
    assert lookups == ["rebind.test"]  # una sola consulta
    assert backend.calls == [(PUBLIC_IP, 80)]  # se conectó a la dirección validada, no al nombre
    assert b"Host: rebind.test" in backend.streams[0].written


async def test_a_redirect_to_an_in_scope_name_that_resolves_to_a_private_address_is_not_followed(monkeypatch):
    fake_dns(monkeypatch, {"www.site.test": [PUBLIC_IP], "internal.site.test": ["10.0.0.5"]})
    backend = FakeBackend({PUBLIC_IP: redirect_response("http://internal.site.test/secret")})
    fetched = await fetch_in_scope(
        "http://www.site.test/", scope="site.test", timeout=3, transport=guarded_transport(backend=backend)
    )

    assert fetched.status_code == 302  # se informa la redirección tal cual
    assert fetched.not_followed == "redirect_target_not_public"
    assert backend.calls == [(PUBLIC_IP, 80)]  # a 10.0.0.5 no se conectó nadie


async def test_the_guard_covers_ipv6_loopback_and_mapped_addresses(monkeypatch):
    for answer in (["::1"], ["::ffff:127.0.0.1"], ["64:ff9b::7f00:1"], ["fe80::1"]):
        fake_dns(monkeypatch, {"v6.test": answer})
        backend = FakeBackend()
        with pytest.raises(BlockedTarget):
            await fetch_in_scope("http://v6.test/", scope="v6.test", timeout=3, transport=guarded_transport(backend=backend))
        assert backend.calls == []


async def test_the_guard_is_really_installed_in_the_httpx_transport():
    transport = guarded_transport()
    assert isinstance(transport._pool._network_backend, GuardedBackend)


def test_it_fails_loudly_if_httpx_changes_its_internals(monkeypatch):
    class NoPool:
        def __init__(self, **kwargs):
            pass

    monkeypatch.setattr(safe_http.httpx, "AsyncHTTPTransport", NoPool)
    with pytest.raises(RuntimeError, match="estructura interna"):
        guarded_transport()


# ── Alcance de las redirecciones ─────────────────────────────────────────────────────────────────────────────────

def _routes(table: dict[str, tuple[int, dict, bytes]]):
    """MockTransport: URL -> (estado, cabeceras, cuerpo). Anota las URL pedidas."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        status, headers, body = table.get(str(request.url), (404, {}, b"not found"))
        return httpx.Response(status, headers=headers, content=body)

    return httpx.MockTransport(handler), seen


def _to(location: str):
    return (302, {"Location": location}, b"")


async def test_redirects_inside_the_domain_are_followed():
    transport, seen = _routes({
        "http://site.test/": _to("https://www.site.test/home"),
        "https://www.site.test/home": _to("/final"),
        "https://www.site.test/final": (200, {"Server": "nginx"}, b"<title>Home</title>"),
    })
    fetched = await fetch_in_scope("http://site.test/", scope="site.test", timeout=3, transport=transport)

    assert (fetched.status_code, fetched.url, fetched.not_followed) == (200, "https://www.site.test/final", None)
    assert len(seen) == 3


@pytest.mark.parametrize(
    "location, reason",
    [
        ("http://169.254.169.254/latest/meta-data/", "out_of_scope"),
        ("http://127.0.0.1:6379/", "out_of_scope"),
        ("http://[::1]/", "out_of_scope"),
        ("https://evil.com/", "out_of_scope"),
        ("https://site.test.evil.com/", "out_of_scope"),  # el dominio como prefijo no cuenta
        ("https://notsite.test/", "out_of_scope"),  # ni como sufijo de otro nombre
        ("https://site.test@evil.com/", "out_of_scope"),  # el host real es lo que viene después de la @
        ("ftp://site.test/file", "unsupported_scheme"),
    ],
)
async def test_redirects_that_leave_the_domain_are_reported_not_followed(location, reason):
    transport, seen = _routes({"http://site.test/": (301, {"Location": location, "Server": "lab"}, b"")})
    fetched = await fetch_in_scope("http://site.test/", scope="site.test", timeout=3, transport=transport)

    assert fetched.status_code == 301
    assert fetched.not_followed == reason
    assert fetched.headers["location"] == location
    assert seen == ["http://site.test/"]  # nunca se pidió el destino


async def test_a_redirect_from_https_to_http_is_not_followed():
    transport, seen = _routes({"https://site.test/": _to("http://site.test/plain")})
    fetched = await fetch_in_scope("https://site.test/", scope="site.test", timeout=3, transport=transport)
    assert fetched.not_followed == "https_downgrade"
    assert seen == ["https://site.test/"]


async def test_http_to_https_upgrade_is_fine():
    transport, _ = _routes({"http://site.test/": _to("https://site.test/"), "https://site.test/": (200, {}, b"ok")})
    fetched = await fetch_in_scope("http://site.test/", scope="site.test", timeout=3, transport=transport)
    assert (fetched.status_code, fetched.not_followed) == (200, None)


async def test_a_redirect_loop_stops_after_three_redirects():
    transport, seen = _routes({"http://site.test/a": _to("/b"), "http://site.test/b": _to("/a")})
    fetched = await fetch_in_scope("http://site.test/a", scope="site.test", timeout=3, transport=transport)
    assert fetched.not_followed == "too_many_redirects"
    assert len(seen) == 4


# ── Recursos ──────────────────────────────────────────────────────────────────────────────────────────────────────

async def test_the_body_is_capped_and_the_rest_is_never_downloaded():
    class Endless(httpx.AsyncByteStream):
        async def __aiter__(self):
            while True:
                yield b"x" * 8192
                await asyncio.sleep(0)

    transport = httpx.MockTransport(lambda request: httpx.Response(200, stream=Endless()))
    fetched = await asyncio.wait_for(
        fetch_in_scope("http://site.test/", scope="site.test", timeout=3, max_body_bytes=10_000, transport=transport), 5
    )
    assert len(fetched.body) == 10_000
    assert fetched.truncated is True


async def test_a_server_that_drips_bytes_cannot_hold_the_request_forever(monkeypatch):
    """Los timeouts de httpx son por operación: un byte cada 0.2 s los renueva siempre. El tope total lo corta."""
    class Drip(httpx.AsyncByteStream):
        async def __aiter__(self):
            while True:
                await asyncio.sleep(0.2)
                yield b"."

    transport = httpx.MockTransport(lambda request: httpx.Response(200, stream=Drip()))
    started = asyncio.get_running_loop().time()
    with pytest.raises(TimeoutError):
        await fetch_in_scope("http://site.test/", scope="site.test", timeout=0.5, max_body_bytes=10**9, transport=transport)
    assert asyncio.get_running_loop().time() - started < 4
