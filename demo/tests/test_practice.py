"""practice.py: los tres sitios de práctica, con certificados reales firmados por la autoridad de la demo."""
import asyncio
import contextlib
import json
import ssl
import struct

import pytest

import practice
from common import OFF_FLAG, TOKEN_FILE

EPHEMERAL = {name: 0 for services in practice.SERVICE_PORTS.values() for name in services}
HOSTNAME = {"shop": "tienda-demo.test", "staging": "pruebas.tienda-demo.test", "ct": "crt.sh"}


def run(coro):
    return asyncio.run(coro)


@contextlib.asynccontextmanager
async def serving(role, state_dir, shared_dir):
    servers = await practice.start_role(role, host="127.0.0.1", ports=EPHEMERAL, state_dir=state_dir, shared_dir=shared_dir)
    try:
        yield {name: server.sockets[0].getsockname()[1] for name, server in servers.items()}
    finally:
        await practice.close_servers(servers)


def trusting(state_dir) -> ssl.SSLContext:
    """Un cliente que verifica certificados como lo hace el motor, con la autoridad de la demo como única confianza."""
    return ssl.create_default_context(cafile=str(state_dir / "pki" / "ca.pem"))


def not_checking() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


async def fetch(port, path, *, context, hostname, method="GET"):
    reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=context, server_hostname=hostname)
    try:
        writer.write(f"{method} {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode())
        raw = await asyncio.wait_for(reader.read(), 5)
    finally:
        writer.close()
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = {key.lower(): value for key, value in (line.split(": ", 1) for line in lines[1:])}
    return int(lines[0].split(" ")[1]), headers, body


# -- la tienda ------------------------------------------------------------------------------------------------------------

def test_shop_answers_over_https_with_a_valid_certificate(state_dir, shared_dir):
    async def scenario():
        async with serving("shop", state_dir, shared_dir) as ports:
            assert set(ports) == {"https"}
            return await fetch(ports["https"], "/", context=trusting(state_dir), hostname=HOSTNAME["shop"])

    status, headers, body = run(scenario())
    assert status == 200
    assert b"<title>Tienda Demo</title>" in body
    assert headers["server"] == "nginx"   # sin versión: no es un hallazgo
    assert headers["x-frame-options"] == "DENY"
    assert "max-age" in headers["strict-transport-security"]
    assert "content-security-policy" not in headers   # le falta una sola protección, a propósito
    assert int(headers["content-length"]) == len(body)


def test_shop_certificate_is_rejected_for_another_name_and_without_the_demo_authority(state_dir, shared_dir):
    async def scenario(context, hostname):
        async with serving("shop", state_dir, shared_dir) as ports:
            await fetch(ports["https"], "/", context=context, hostname=hostname)

    with pytest.raises(ssl.SSLCertVerificationError):
        run(scenario(trusting(state_dir), "otro-sitio.test"))   # nombre equivocado
    with pytest.raises(ssl.SSLCertVerificationError):
        run(scenario(ssl.create_default_context(), HOSTNAME["shop"]))   # sin la autoridad de la demo no hay confianza


def test_shop_serves_the_verification_token_exactly_when_published(state_dir, shared_dir):
    token = "recon-verify-0b6f9d2e-3c1a-4e8b-9a77-5d2f1c0e4a10"

    async def scenario():
        async with serving("shop", state_dir, shared_dir) as ports:
            ask = lambda: fetch(ports["https"], "/.well-known/recon-verification.txt",  # noqa: E731
                                context=trusting(state_dir), hostname=HOSTNAME["shop"])
            before = await ask()
            (shared_dir / TOKEN_FILE).write_text(token)
            after = await ask()
            (shared_dir / TOKEN_FILE).unlink()
            retired = await ask()
            return before, after, retired

    before, after, retired = run(scenario())
    assert before[0] == 404
    assert after[0] == 200 and after[2] == token.encode()   # el cuerpo es el código, sin nada más
    assert retired[0] == 404


def test_shop_does_not_serve_anything_else_from_disk(shared_dir):
    (shared_dir / TOKEN_FILE).write_text("recon-verify-x")
    (shared_dir / "secreto.txt").write_text("no")
    for target in ("/secreto.txt", f"/{TOKEN_FILE}", "/.well-known/", "/.well-known/recon-verification.txt/../../secreto.txt",
                   "/..%2fsecreto.txt", "//etc/passwd"):
        assert practice.build_reply("shop", "GET", target, shared_dir).status == 404


def test_oversized_or_empty_token_files_are_ignored(shared_dir):
    (shared_dir / TOKEN_FILE).write_bytes(b"x" * 5000)
    assert practice.read_token(shared_dir) is None
    (shared_dir / TOKEN_FILE).write_bytes(b"")
    assert practice.read_token(shared_dir) is None


# -- el servidor de pruebas olvidado --------------------------------------------------------------------------------------

def test_staging_certificate_is_expired(state_dir, shared_dir):
    async def scenario(context):
        async with serving("staging", state_dir, shared_dir) as ports:
            return await fetch(ports["https"], "/", context=context, hostname=HOSTNAME["staging"])

    with pytest.raises(ssl.SSLCertVerificationError, match="expired"):
        run(scenario(trusting(state_dir)))
    status, headers, body = run(scenario(not_checking()))   # sin verificar, el sitio responde igual
    assert status == 200
    assert headers["server"] == "Apache/2.4.29 (Ubuntu)"
    assert headers["x-powered-by"] == "PHP/7.2.24"
    assert b"WordPress" in body
    for protection in ("content-security-policy", "x-frame-options", "strict-transport-security"):
        assert protection not in headers


def test_staging_opens_the_ports_a_scan_should_find(state_dir, shared_dir):
    async def scenario():
        async with serving("staging", state_dir, shared_dir) as ports:
            assert set(ports) == {"ftp", "ssh", "https", "mysql"}
            out = {}
            for name in ("ftp", "ssh", "mysql"):
                reader, writer = await asyncio.open_connection("127.0.0.1", ports[name])
                out[name] = await asyncio.wait_for(reader.read(1024), 2)
                writer.close()
            return out

    banners = run(scenario())
    assert banners["ftp"] == b"220 (vsFTPd 3.0.3)\r\n"
    assert banners["ssh"].startswith(b"SSH-2.0-OpenSSH_7.6p1")
    # El saludo de MySQL: 3 bytes de largo, 1 de secuencia, protocolo 10 y la versión.
    greeting = banners["mysql"]
    assert struct.unpack("<I", greeting[:3] + b"\x00")[0] == len(greeting) - 4
    assert greeting[3] == 0 and greeting[4] == 10
    assert greeting[5:].split(b"\x00", 1)[0] == b"5.7.33-0ubuntu0.18.04.1"


def test_greeting_services_are_inert(state_dir, shared_dir, monkeypatch):
    monkeypatch.setattr(practice, "IDLE_TIMEOUT", 0.3)

    async def scenario():
        async with serving("staging", state_dir, shared_dir) as ports:
            results = {}
            for name in ("ftp", "ssh", "mysql"):
                reader, writer = await asyncio.open_connection("127.0.0.1", ports[name])
                await reader.read(1024)   # el saludo
                writer.write(b"USER root\r\nPASS root\r\n")   # un intento de ingreso
                await writer.drain()
                try:
                    reply = await asyncio.wait_for(reader.read(1024), 2)   # no hay respuesta: el servicio cierra la conexión
                except asyncio.TimeoutError:
                    reply = b"<colgado>"
                results[name] = reply
                writer.close()
            return results

    assert run(scenario()) == {"ftp": b"", "ssh": b"", "mysql": b""}


def test_staging_goes_off_and_on_with_the_flag(state_dir, shared_dir):
    async def scenario():
        supervisor = practice.Supervisor("staging", host="127.0.0.1", ports=EPHEMERAL, state_dir=state_dir, shared_dir=shared_dir)
        try:
            await supervisor.step()
            first = {name: server.sockets[0].getsockname()[1] for name, server in supervisor.servers.items()}
            (shared_dir / OFF_FLAG).write_text("off\n")
            await supervisor.step()
            assert supervisor.servers == {}
            refused = 0
            for port in first.values():
                with pytest.raises(OSError):
                    await asyncio.open_connection("127.0.0.1", port)
                refused += 1
            (shared_dir / OFF_FLAG).unlink()
            await supervisor.step()
            assert set(supervisor.servers) == {"ftp", "ssh", "https", "mysql"}
            return refused
        finally:
            await supervisor.stop()

    assert run(scenario()) == 4


def test_only_staging_reacts_to_the_off_flag(state_dir, shared_dir):
    (shared_dir / OFF_FLAG).write_text("off\n")

    async def scenario(role):
        supervisor = practice.Supervisor(role, host="127.0.0.1", ports=EPHEMERAL, state_dir=state_dir, shared_dir=shared_dir)
        try:
            await supervisor.step()
            return sorted(supervisor.servers)
        finally:
            await supervisor.stop()

    assert run(scenario("shop")) == ["https"]
    assert run(scenario("ct")) == ["https"]
    assert run(scenario("staging")) == []


# -- el registro de certificados ------------------------------------------------------------------------------------------

def test_ct_lists_only_the_forgotten_subdomain_for_the_demo_domain(state_dir, shared_dir):
    async def scenario(target):
        async with serving("ct", state_dir, shared_dir) as ports:
            return await fetch(ports["https"], target, context=trusting(state_dir), hostname=HOSTNAME["ct"])

    status, headers, body = run(scenario("/?q=%25.tienda-demo.test&output=json"))   # lo mismo que manda el motor
    assert status == 200 and headers["content-type"].startswith("application/json")
    names = {line for entry in json.loads(body) for line in entry["name_value"].split("\n")}
    assert names == {"pruebas.tienda-demo.test"}   # el dominio principal no está: el motor ya lo escanea por nombre

    assert json.loads(run(scenario("/?q=%25.otro-dominio.com&output=json"))[2]) == []
    assert json.loads(run(scenario("/"))[2]) == []
    assert run(scenario("/otra-cosa"))[0] == 404


def test_ct_response_has_the_fields_the_engine_reads():
    entries = json.loads(practice.ct_listing("q=%25.tienda-demo.test&output=json"))
    assert entries and all(isinstance(entry["name_value"], str) for entry in entries)


# -- comportamiento general -----------------------------------------------------------------------------------------------

def test_replies_for_other_methods_and_paths(shared_dir):
    assert practice.build_reply("shop", "POST", "/", shared_dir).status == 405
    assert practice.build_reply("staging", "DELETE", "/", shared_dir).status == 405
    assert practice.build_reply("shop", "GET", "/no-existe", shared_dir).status == 404
    assert practice.build_reply("ct", "GET", "/no-existe", shared_dir).status == 404
    head = practice.build_reply("shop", "HEAD", "/", shared_dir).render(head_only=True)
    assert head.endswith(b"\r\n\r\n") and b"Content-Length:" in head


def test_garbage_and_huge_requests_do_not_break_the_site(state_dir, shared_dir):
    async def scenario():
        async with serving("shop", state_dir, shared_dir) as ports:
            context = trusting(state_dir)
            for payload in (b"basura sin formato\r\n\r\n", b"GET / HTTP/1.1\r\n" + b"X: " + b"a" * 20000 + b"\r\n\r\n", b"\x00\x01\x02\r\n\r\n"):
                reader, writer = await asyncio.open_connection("127.0.0.1", ports["https"], ssl=context, server_hostname=HOSTNAME["shop"])
                writer.write(payload)
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(reader.read(), 3)
                writer.close()
            return await fetch(ports["https"], "/", context=context, hostname=HOSTNAME["shop"])   # sigue respondiendo

    assert run(scenario())[0] == 200


def test_main_rejects_an_unknown_role(monkeypatch, capsys):
    monkeypatch.setenv("PRACTICE_ROLE", "otro")
    assert practice.main() == 2
    assert "PRACTICE_ROLE" in capsys.readouterr().err


def test_default_ports_are_the_real_ones():
    assert practice.SERVICE_PORTS == {
        "shop": {"https": 443},
        "staging": {"ftp": 21, "ssh": 22, "https": 443, "mysql": 3306},
        "ct": {"https": 443},
    }
