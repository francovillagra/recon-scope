"""Sitios de práctica de la demo de Recon Scope.

Un solo programa con tres personajes, según la variable PRACTICE_ROLE. Cada uno corre en su propio contenedor y tiene en la red
de la demo el nombre que le toca:

  shop     tienda-demo.test           Un sitio sano, con certificado vigente y casi todas las protecciones. Sirve el archivo de
                                      verificación cuando la consola lo publica: así se demuestra que el dominio es "del cliente".
  staging  pruebas.tienda-demo.test   El servidor de pruebas que nadie recuerda: certificado vencido, versiones a la vista y
                                      puertos de administración y de base de datos abiertos. Se puede "apagar" desde la consola.
  ct       crt.sh                     El registro público de certificados que consulta el motor para descubrir subdominios. Aquí
                                      contesta una lista fija, así el motor no sale a internet.

Nada de esto es un servicio real. Los puertos de FTP, SSH y base de datos solo muestran el saludo con el que se anuncia cada programa
y no hacen nada más (no hay archivos, ni usuarios, ni datos): alcanza para que un escaneo los encuentre, que es lo que se muestra.
Solo usa la biblioteca estándar. Ver demo/README.md.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import ssl
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable, Optional
from urllib.parse import parse_qs, urlsplit

from common import (
    DEFAULT_SHARED_DIR, DEFAULT_STATE_DIR, DOMAIN, OFF_FLAG, ROLES, STAGING_HOST, TOKEN_FILE, VERIFICATION_PATH,
)

STATE_DIR = Path(os.environ.get("DEMO_STATE_DIR", DEFAULT_STATE_DIR))
SHARED_DIR = Path(os.environ.get("DEMO_SHARED_DIR", DEFAULT_SHARED_DIR))

MAX_REQUEST_BYTES = 8192        # una petición más larga no es de un escaneo: se cierra
IO_TIMEOUT = 5.0                # segundos para leer una petición o escribir la respuesta
IDLE_TIMEOUT = 3.0              # cuánto espera un servicio de "saludo" a que el cliente diga algo antes de cerrar
POLL_SECONDS = 0.5              # cada cuánto mira el servidor de pruebas si la consola lo apagó o lo prendió
CLOSE_GRACE = 6.0               # al apagar un puerto, cuánto esperar a que terminen las conexiones en curso
TOKEN_MAX_BYTES = 256


def log(role: str, message: str) -> None:
    print(f"[{role}] {message}", flush=True)


# -- páginas y respuestas HTTP --------------------------------------------------------------------------------------------

SHOP_PAGE = (
    '<!doctype html>\n<html lang="es"><head><meta charset="utf-8"><title>Tienda Demo</title></head>\n'
    "<body><h1>Tienda Demo</h1><p>Sitio de práctica de Recon Scope. No es una tienda real.</p></body></html>\n"
)
STAGING_PAGE = (
    '<!doctype html>\n<html lang="es"><head><meta charset="utf-8">'
    "<title>Tienda Demo (pruebas) - Just another WordPress site</title></head>\n"
    "<body><h1>Tienda Demo (pruebas)</h1><p>Sitio de práctica de Recon Scope. Entorno de pruebas olvidado.</p></body></html>\n"
)

# Lo que cada sitio anuncia en sus cabeceras. La tienda protege casi todo (le falta Content-Security-Policy); el servidor de
# pruebas no protege nada y anuncia hasta las versiones.
SHOP_HEADERS = (
    ("Server", "nginx"),
    ("X-Frame-Options", "DENY"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("X-Content-Type-Options", "nosniff"),
)
STAGING_HEADERS = (
    ("Server", "Apache/2.4.29 (Ubuntu)"),
    ("X-Powered-By", "PHP/7.2.24"),
)
CT_HEADERS = (("Server", "nginx"),)

REASONS = {200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed"}


@dataclass(frozen=True)
class Reply:
    status: int
    body: bytes = b""
    content_type: str = "text/html; charset=utf-8"
    headers: tuple[tuple[str, str], ...] = ()

    def render(self, *, head_only: bool = False) -> bytes:
        lines = [f"HTTP/1.1 {self.status} {REASONS.get(self.status, 'OK')}"]
        lines += [f"{name}: {value}" for name, value in self.headers]
        lines += [f"Content-Type: {self.content_type}", f"Content-Length: {len(self.body)}", "Connection: close", "", ""]
        return "\r\n".join(lines).encode("latin-1") + (b"" if head_only else self.body)


def read_token(shared_dir: Path) -> Optional[bytes]:
    """El contenido que la consola publicó para verificar el dominio, o None si todavía no lo publicó."""
    try:
        with open(shared_dir / TOKEN_FILE, "rb") as handle:
            data = handle.read(TOKEN_MAX_BYTES + 1)
    except OSError:
        return None
    if not data or len(data) > TOKEN_MAX_BYTES:
        return None
    return data


# Entradas que el "registro de certificados" de práctica devuelve para tienda-demo.test. El apex no está a propósito: el motor lo
# escanea de todos modos por nombre, y listarlo acá lo escanearía dos veces (por nombre y por dirección).
CT_ENTRIES = (
    {
        "issuer_ca_id": 1,
        "issuer_name": "O=Recon Scope Demo, CN=Recon Scope Demo CA",
        "common_name": STAGING_HOST,
        "name_value": STAGING_HOST,
        "id": 1001,
        "entry_timestamp": "2024-02-14T10:21:07.411",
        "not_before": "2024-02-14T00:00:00",
        "not_after": "2025-02-14T00:00:00",
        "serial_number": "0a1b2c3d4e5f",
    },
)


def ct_listing(query: str) -> bytes:
    wanted = parse_qs(query).get("q", [""])[0]
    entries = list(CT_ENTRIES) if wanted == f"%.{DOMAIN}" else []   # cualquier otro dominio: sin certificados
    return json.dumps(entries).encode("utf-8")


def build_reply(role: str, method: str, target: str, shared_dir: Path) -> Reply:
    """La respuesta de cada sitio. Función pura (salvo leer el archivo de verificación), para poder probarla sin red."""
    headers = {"shop": SHOP_HEADERS, "staging": STAGING_HEADERS, "ct": CT_HEADERS}[role]
    if method not in ("GET", "HEAD"):
        return Reply(405, b"", "text/plain; charset=utf-8", headers)
    url = urlsplit(target)

    if role == "ct":
        if url.path == "/":
            return Reply(200, ct_listing(url.query), "application/json; charset=utf-8", headers)
        return Reply(404, b"[]", "application/json; charset=utf-8", headers)

    if role == "shop" and url.path == VERIFICATION_PATH:
        token = read_token(shared_dir)
        if token is None:
            return Reply(404, b"Not found\n", "text/plain; charset=utf-8", headers)
        return Reply(200, token, "text/plain; charset=utf-8", headers)

    if url.path == "/":
        page = SHOP_PAGE if role == "shop" else STAGING_PAGE
        return Reply(200, page.encode("utf-8"), "text/html; charset=utf-8", headers)
    return Reply(404, b"Not found\n", "text/plain; charset=utf-8", headers)


async def close_quietly(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 2.0)
    except Exception:  # noqa: BLE001 - un cliente que corta a la mitad no es un problema
        pass


def http_handler(role: str, shared_dir: Path) -> Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            try:
                raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), IO_TIMEOUT)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, OSError):
                return
            parts = raw.split(b"\r\n", 1)[0].decode("latin-1").split(" ")
            if len(parts) != 3 or not parts[2].startswith("HTTP/"):
                reply, label = Reply(400, b"", "text/plain; charset=utf-8"), "petición inválida"
            else:
                method, target = parts[0], parts[1]
                reply, label = build_reply(role, method, target, shared_dir), f"{method} {urlsplit(target).path}"
            writer.write(reply.render(head_only=label.startswith("HEAD ")))
            await asyncio.wait_for(writer.drain(), IO_TIMEOUT)
            log(role, f"{label} -> {reply.status}")
        except (asyncio.TimeoutError, OSError):
            pass
        finally:
            await close_quietly(writer)

    return handle


# -- servicios que solo saludan -------------------------------------------------------------------------------------------

def mysql_greeting() -> bytes:
    """El primer paquete que manda un MySQL 5.7 al recibir una conexión (versión, número de conexión y datos para la clave).
    Los bytes de relleno son fijos y no valen nada: nunca se completa un ingreso."""
    payload = (
        bytes([10]) + b"5.7.33-0ubuntu0.18.04.1\x00"
        + struct.pack("<I", 8) + b"abcdefgh" + b"\x00"
        + struct.pack("<H", 0xF7FF) + bytes([33]) + struct.pack("<H", 2) + struct.pack("<H", 0x81FF)
        + bytes([21]) + b"\x00" * 10
        + b"ijklmnopqrst\x00" + b"mysql_native_password\x00"
    )
    return struct.pack("<I", len(payload))[:3] + b"\x00" + payload


GREETINGS = {
    "ftp": b"220 (vsFTPd 3.0.3)\r\n",
    "ssh": b"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7\r\n",
    "mysql": mysql_greeting(),
}


def greeting_handler(role: str, name: str) -> Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]:
    banner = GREETINGS[name]

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            writer.write(banner)
            await asyncio.wait_for(writer.drain(), IO_TIMEOUT)
            log(role, f"saludo de {name} enviado")
            try:
                await asyncio.wait_for(reader.read(1024), IDLE_TIMEOUT)   # no contesta nada: espera que el cliente cierre
            except (asyncio.TimeoutError, OSError):
                pass
        except (asyncio.TimeoutError, OSError):
            pass
        finally:
            await close_quietly(writer)

    return handle


# -- qué escucha cada sitio -----------------------------------------------------------------------------------------------

SERVICE_PORTS: dict[str, dict[str, int]] = {
    "shop": {"https": 443},
    "staging": {"ftp": 21, "ssh": 22, "https": 443, "mysql": 3306},
    "ct": {"https": 443},
}


def tls_context(pki_dir: Path, role: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(pki_dir / f"{role}.pem", pki_dir / f"{role}.key")
    return context


async def start_role(
    role: str, *, host: str = "0.0.0.0", ports: Optional[dict[str, int]] = None,
    state_dir: Path = STATE_DIR, shared_dir: Path = SHARED_DIR,
) -> dict[str, asyncio.AbstractServer]:
    """Abre todos los puertos del sitio. `ports` reemplaza los puertos de siempre (las pruebas usan puertos libres)."""
    servers: dict[str, asyncio.AbstractServer] = {}
    try:
        for name, default_port in SERVICE_PORTS[role].items():
            port = (ports or {}).get(name, default_port)
            if name == "https":
                servers[name] = await asyncio.start_server(
                    http_handler(role, shared_dir), host, port, ssl=tls_context(state_dir / "pki", role),
                    limit=MAX_REQUEST_BYTES, backlog=64,
                )
            else:
                servers[name] = await asyncio.start_server(greeting_handler(role, name), host, port, backlog=64)
    except BaseException:
        await close_servers(servers)
        raise
    return servers


async def close_servers(servers: dict[str, asyncio.AbstractServer]) -> None:
    for server in servers.values():
        server.close()
    for server in servers.values():
        try:
            await asyncio.wait_for(server.wait_closed(), CLOSE_GRACE)
        except (asyncio.TimeoutError, OSError):
            pass
    servers.clear()


class Supervisor:
    """Mantiene abiertos los puertos del sitio. El servidor de pruebas se apaga y se prende cuando la consola crea o borra el
    archivo `staging-off` de la carpeta compartida: así se muestra qué cambia en el informe cuando el cliente da de baja un
    servidor olvidado."""

    def __init__(
        self, role: str, *, host: str = "0.0.0.0", ports: Optional[dict[str, int]] = None,
        state_dir: Path = STATE_DIR, shared_dir: Path = SHARED_DIR,
    ) -> None:
        self.role, self.host, self.ports = role, host, ports
        self.state_dir, self.shared_dir = state_dir, shared_dir
        self.servers: dict[str, asyncio.AbstractServer] = {}

    def wanted_on(self) -> bool:
        return not (self.role == "staging" and (self.shared_dir / OFF_FLAG).exists())

    async def step(self) -> None:
        if self.wanted_on() and not self.servers:
            self.servers = await start_role(
                self.role, host=self.host, ports=self.ports, state_dir=self.state_dir, shared_dir=self.shared_dir
            )
            log(self.role, "encendido: " + ", ".join(
                f"{name} ({server.sockets[0].getsockname()[1]})" for name, server in self.servers.items()
            ))
        elif not self.wanted_on() and self.servers:
            await close_servers(self.servers)
            log(self.role, "apagado: no responde en ningún puerto")

    async def stop(self) -> None:
        await close_servers(self.servers)


async def run(role: str) -> int:
    supervisor = Supervisor(role)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)   # docker stop manda SIGTERM: como proceso 1 se ignoraría sin esto
    try:
        await supervisor.step()   # si no puede abrir los puertos, falla ahora y Docker lo muestra
    except OSError as exc:
        log(role, f"no se pudieron abrir los puertos: {exc}")
        return 1
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), POLL_SECONDS)
        except asyncio.TimeoutError:
            try:
                await supervisor.step()
            except OSError as exc:
                log(role, f"no se pudo cambiar el estado de los puertos: {exc}")
    await supervisor.stop()
    return 0


def main() -> int:
    role = os.environ.get("PRACTICE_ROLE", "")
    if role not in ROLES:
        print(f"PRACTICE_ROLE tiene que ser uno de: {', '.join(ROLES)}", file=sys.stderr)
        return 2
    logging.getLogger("asyncio").setLevel(logging.ERROR)   # los escaneos cortan apretones TLS a propósito (certificado vencido)
    return asyncio.run(run(role))


if __name__ == "__main__":
    sys.exit(main())
