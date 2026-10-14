"""La guarda aplicada a cada módulo que toca la red: puertos, huella HTTP/TLS, subdominios y verificación de dominio."""
import asyncio
import json

import httpx
import pytest

from app.config import settings
from app.recon import fingerprint, ports, subdomains
from app.recon.netguard import BlockedTarget
from app.services.domain_verification import verify_well_known_file

from .netfakes import LocalServer, fake_dns

PUBLIC_IP = "93.184.216.34"


# ── Puertos ──────────────────────────────────────────────────────────────────────────────────────────────────────

async def test_port_scan_does_not_touch_a_name_that_points_to_loopback(monkeypatch):
    fake_dns(monkeypatch, {"evil.test": ["127.0.0.1"]})
    async with LocalServer(banner=b"SSH-2.0-internal-canary\r\n") as internal:
        monkeypatch.setattr(ports, "_ports_for_range", lambda _: [internal.port])
        with pytest.raises(BlockedTarget):
            await ports.scan_ports("evil.test", "top-100", timeout=2)
        assert internal.connections == 0


async def test_port_scan_does_not_touch_an_ip_literal_in_the_internal_range(monkeypatch):
    async with LocalServer(banner=b"canary") as internal:
        monkeypatch.setattr(ports, "_ports_for_range", lambda _: [internal.port])
        with pytest.raises(BlockedTarget):
            await ports.scan_ports("127.0.0.1", "top-100", timeout=2)
        assert internal.connections == 0


async def test_port_scan_with_the_flag_on_still_finds_the_open_port_and_its_banner(monkeypatch):
    """Control: con ALLOW_PRIVATE_TARGETS el escáner sigue funcionando contra una red propia."""
    monkeypatch.setattr(settings, "ALLOW_PRIVATE_TARGETS", True)
    fake_dns(monkeypatch, {"lab.test": ["127.0.0.1"]})
    async with LocalServer(banner=b"SSH-2.0-OpenSSH_9.6\r\n") as server:
        monkeypatch.setattr(ports, "_ports_for_range", lambda _: [server.port])
        results = await ports.scan_ports("lab.test", "top-100", timeout=2)
    assert [(r.host, r.port, r.banner) for r in results] == [("lab.test", server.port, "SSH-2.0-OpenSSH_9.6")]


async def test_port_scan_resolves_once_and_connects_every_port_to_the_validated_address(monkeypatch):
    lookups: list[str] = []
    answers = iter([[PUBLIC_IP]] + [["127.0.0.1"]] * 50)

    from app.recon import netguard

    async def rebinding_lookup(host, port):
        lookups.append(host)
        return next(answers)

    monkeypatch.setattr(netguard, "_lookup", rebinding_lookup)
    monkeypatch.setattr(ports, "_ports_for_range", lambda _: [22, 80, 443, 8080])
    attempted: list[tuple] = []

    async def refuse(host, port, **kwargs):
        attempted.append((host, port))
        raise ConnectionRefusedError

    monkeypatch.setattr(ports.asyncio, "open_connection", refuse)

    assert await ports.scan_ports("rebind.test", "top-100", timeout=1) == []
    assert lookups == ["rebind.test"]
    assert sorted(attempted) == [(PUBLIC_IP, 22), (PUBLIC_IP, 80), (PUBLIC_IP, 443), (PUBLIC_IP, 8080)]


async def test_port_scan_of_a_name_that_does_not_resolve_is_empty_not_an_error(monkeypatch):
    fake_dns(monkeypatch, {})
    assert await ports.scan_ports("nope.test", "top-100", timeout=1) == []


# ── Huella HTTP y TLS ────────────────────────────────────────────────────────────────────────────────────────────

async def test_http_fingerprint_does_not_touch_a_name_that_points_to_loopback(monkeypatch):
    fake_dns(monkeypatch, {"evil.test": ["127.0.0.1"]})
    async with LocalServer() as internal:
        with pytest.raises(BlockedTarget):
            await fingerprint.fingerprint_http(f"http://evil.test:{internal.port}/", 2, "evil.test")
        assert internal.connections == 0


async def test_http_fingerprint_reads_title_and_server_and_reports_an_unfollowed_redirect(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_PRIVATE_TARGETS", True)
    fake_dns(monkeypatch, {"lab.test": ["127.0.0.1"]})
    async with LocalServer() as server:
        fp = await fingerprint.fingerprint_http(f"http://lab.test:{server.port}/", 2, "lab.test")
    assert (fp.status_code, fp.server_header, fp.title) == (200, "lab/1.0", "hi")

    from .netfakes import redirect_response

    async with LocalServer(reply=redirect_response("https://elsewhere.example/")) as server:
        fp = await fingerprint.fingerprint_http(f"http://lab.test:{server.port}/", 2, "lab.test")
    assert fp.status_code == 302 and fp.response_headers["location"] == "https://elsewhere.example/"
    assert server.connections == 1  # no se fue al sitio ajeno


async def test_http_fingerprint_of_a_closed_port_is_none(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_PRIVATE_TARGETS", True)
    async with LocalServer() as server:
        port = server.port
    assert await fingerprint.fingerprint_http(f"http://127.0.0.1:{port}/", 2, "127.0.0.1") is None


async def test_tls_fingerprint_does_not_touch_a_name_that_points_to_an_internal_range(monkeypatch):
    fake_dns(monkeypatch, {"evil.test": ["10.0.0.5"]})
    with pytest.raises(BlockedTarget):
        await fingerprint.fingerprint_tls("evil.test", 2)


async def test_tls_fingerprint_connects_to_the_validated_address_and_verifies_the_name(monkeypatch):
    fake_dns(monkeypatch, {"site.test": [PUBLIC_IP]})
    seen: dict = {}

    async def fake_connect(addresses, port, timeout, *, ssl_context=None, server_hostname=None):
        seen.update(addresses=addresses, port=port, server_hostname=server_hostname, verify=ssl_context.verify_mode)
        raise ConnectionRefusedError

    monkeypatch.setattr(fingerprint, "connect_any", fake_connect)
    assert await fingerprint.fingerprint_tls("site.test", 2) is None
    assert seen["addresses"] == [PUBLIC_IP] and seen["port"] == 443
    assert seen["server_hostname"] == "site.test"  # SNI y verificación contra el nombre, no contra la IP
    import ssl

    assert seen["verify"] == ssl.CERT_REQUIRED


async def test_tls_fingerprint_of_a_name_that_does_not_resolve_is_none(monkeypatch):
    fake_dns(monkeypatch, {})
    assert await fingerprint.fingerprint_tls("nope.test", 2) is None


# ── Verificación de dominio por archivo ────────────────────────────────────────────────────────────────────────────

TOKEN = "recon-verify-11111111-2222-3333-4444-555555555555"


def _wk(table):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        status, headers, body = table.get(str(request.url), (404, {}, b""))
        return httpx.Response(status, headers=headers, content=body)

    return httpx.MockTransport(handler), seen


WK = "https://site.test/.well-known/recon-verification.txt"


async def test_well_known_verification_accepts_the_exact_token():
    transport, _ = _wk({WK: (200, {}, f"{TOKEN}\n".encode())})
    assert await verify_well_known_file("site.test", TOKEN, transport=transport) is True


@pytest.mark.parametrize(
    "response",
    [
        (200, {}, b"otro-token"),
        (200, {}, f"{TOKEN} y algo más".encode()),
        (200, {}, f"{TOKEN}{' ' * 10_000}x".encode()),  # más grande que un token: no puede serlo
        (404, {}, TOKEN.encode()),
        (500, {}, TOKEN.encode()),
    ],
)
async def test_well_known_verification_rejects_anything_else(response):
    transport, _ = _wk({WK: response})
    assert await verify_well_known_file("site.test", TOKEN, transport=transport) is False


async def test_well_known_verification_follows_redirects_inside_the_domain_only():
    # apex -> www: lo habitual; el archivo lo publica el mismo dominio
    transport, _ = _wk({
        WK: (301, {"Location": "https://www.site.test/.well-known/recon-verification.txt"}, b""),
        "https://www.site.test/.well-known/recon-verification.txt": (200, {}, TOKEN.encode()),
    })
    assert await verify_well_known_file("site.test", TOKEN, transport=transport) is True

    # a un sitio ajeno que sirva el token: no demuestra control del dominio
    transport, seen = _wk({
        WK: (301, {"Location": "https://attacker-controlled.example/token.txt"}, b""),
        "https://attacker-controlled.example/token.txt": (200, {}, TOKEN.encode()),
    })
    assert await verify_well_known_file("site.test", TOKEN, transport=transport) is False
    assert seen == [WK]


async def test_well_known_verification_does_not_connect_to_a_domain_that_points_inside(monkeypatch):
    fake_dns(monkeypatch, {"victim.test": ["127.0.0.1"]})
    with pytest.raises(BlockedTarget):
        await verify_well_known_file("victim.test", TOKEN)

    # Control: sin la guarda el motor sí intenta conectarse (acá nadie escucha en el 443, así que simplemente falla).
    monkeypatch.setattr(settings, "ALLOW_PRIVATE_TARGETS", True)
    assert await verify_well_known_file("victim.test", TOKEN) is False


# ── Subdominios ──────────────────────────────────────────────────────────────────────────────────────────────────

def _crtsh(entries, monkeypatch, *, limit=None):
    body = json.dumps(entries).encode()
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=body))
    real = subdomains.httpx.AsyncClient
    monkeypatch.setattr(subdomains.httpx, "AsyncClient", lambda **kw: real(transport=transport, **kw))
    if limit:
        monkeypatch.setattr(subdomains, "CRTSH_MAX_BYTES", limit)


async def test_crtsh_names_are_validated_before_they_reach_a_url(monkeypatch):
    _crtsh(
        [{"name_value": "WWW.Site.test\n*.api.site.test\nsite.test"},
         {"name_value": "bad host.site.test\nx@site.test\na/b.site.test\n-x.site.test\nx..site.test\nevil.example"},
         {"name_value": "a:80.site.test\n127.0.0.1.site.test\nok-1.site.test"},
         {"name_value": 7}, {"other": 1}, "text"],
        monkeypatch,
    )
    assert await subdomains._fetch_crtsh("site.test") == {
        "www.site.test", "api.site.test", "site.test", "127.0.0.1.site.test", "ok-1.site.test",
    }


async def test_crtsh_answer_that_is_not_a_list_gives_no_names(monkeypatch):
    _crtsh({"error": "rate limited"}, monkeypatch)
    assert await subdomains._fetch_crtsh("site.test") == set()


async def test_crtsh_answer_bigger_than_the_cap_is_refused(monkeypatch):
    _crtsh([{"name_value": f"h{i}.site.test"} for i in range(200)], monkeypatch, limit=1000)
    with pytest.raises(subdomains.CrtShTooLarge):
        await subdomains._fetch_crtsh("site.test")


async def test_crtsh_redirects_are_not_followed(monkeypatch):
    transport = httpx.MockTransport(lambda request: httpx.Response(302, headers={"Location": "http://169.254.169.254/"}))
    real = subdomains.httpx.AsyncClient
    monkeypatch.setattr(subdomains.httpx, "AsyncClient", lambda **kw: real(transport=transport, **kw))
    with pytest.raises(httpx.HTTPStatusError):
        await subdomains._fetch_crtsh("site.test")


async def test_subdomains_resolving_to_internal_addresses_lose_their_address_and_are_marked(monkeypatch):
    _crtsh([{"name_value": "pub.site.test\ninternal.site.test\nmixed.site.test\nmeta.site.test\nnone.site.test"}], monkeypatch)
    answers = {
        "pub.site.test": [PUBLIC_IP],
        "internal.site.test": ["10.1.2.3"],
        "mixed.site.test": [PUBLIC_IP, "127.0.0.1"],
        "meta.site.test": ["169.254.169.254"],
        "none.site.test": [],
    }

    async def resolve(hostname):
        return answers[hostname]

    monkeypatch.setattr(subdomains, "_resolve_a", resolve)
    found = {r.hostname: (r.resolved_ip, r.skipped_reason) for r in (await subdomains.enumerate_subdomains("site.test")).results}
    assert found == {
        "pub.site.test": (PUBLIC_IP, None),
        "internal.site.test": (None, "non_public_address"),
        "mixed.site.test": (None, "non_public_address"),
        "meta.site.test": (None, "non_public_address"),
        "none.site.test": (None, None),
    }


async def test_with_the_flag_on_internal_addresses_are_kept(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_PRIVATE_TARGETS", True)
    _crtsh([{"name_value": "intranet.site.test"}], monkeypatch)

    async def resolve(hostname):
        return ["10.1.2.3"]

    monkeypatch.setattr(subdomains, "_resolve_a", resolve)
    (result,) = (await subdomains.enumerate_subdomains("site.test")).results
    assert (result.resolved_ip, result.skipped_reason) == ("10.1.2.3", None)
