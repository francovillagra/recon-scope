"""
Piezas de seguridad HTTP del motor: tope de tamaño del cuerpo, cabeceras de seguridad e IP del cliente.

Los dos middleware son ASGI puros (no `BaseHTTPMiddleware`): ven el cuerpo mientras llega y no lo guardan entero
en memoria para decidir.
"""
import ipaddress
import logging
from typing import Optional

from fastapi import HTTPException, Request
from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import settings

logger = logging.getLogger(__name__)

_SECURITY_HEADERS = {
    # Es una API JSON: nada de lo que devuelve debe interpretarse como página, guardarse en cachés ni embeberse.
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000",  # los navegadores lo ignoran por http (desarrollo local)
}


def security_headers() -> dict[str, str]:
    return dict(_SECURITY_HEADERS)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in _SECURITY_HEADERS.items():
                    headers.setdefault(name, value)
            await send(message)

        await self.app(scope, receive, send_with_headers)


class BodyLimitMiddleware:
    """Rechaza con 413 los cuerpos de más de `max_bytes`, tanto si declaran su tamaño (Content-Length) como si
    llegan por partes sin declararlo (Transfer-Encoding: chunked)."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = MutableHeaders(scope=scope).get("content-length")
        if declared is not None:
            try:
                size = int(declared)
            except ValueError:
                size = -1
            if size < 0:
                await self._reject(400, "Invalid Content-Length", scope, receive, send)
                return
            if size > self.max_bytes:
                await self._reject(413, "Request body too large", scope, receive, send)
                return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    # HTTPException: FastAPI la deja pasar tal cual y se responde 413 (cualquier otra
                    # excepción al leer el cuerpo la convertiría en un 400 genérico).
                    raise HTTPException(status_code=413, detail="Request body too large")
            return message

        await self.app(scope, limited_receive, send)

    @staticmethod
    async def _reject(status_code: int, detail: str, scope: Scope, receive: Receive, send: Send) -> None:
        # Sin leer el cuerpo; se pide cerrar la conexión para no tener que consumirlo.
        response = JSONResponse({"detail": detail}, status_code=status_code, headers={"Connection": "close"})
        await response(scope, receive, send)


_warned_forwarded = False


def client_ip(request: Request) -> Optional[str]:
    """IP del cliente para límites de ritmo y auditoría (None si no se puede saber).

    Detrás de un proxy (Railway) la IP del socket es la del proxy, así que hay que leer X-Forwarded-For; pero ese
    encabezado lo puede escribir el cliente. Por eso se confía solo en lo que agregaron los proxies propios:
    con TRUSTED_PROXY_COUNT=N se toma la N-ésima entrada empezando por la derecha (la que anotó el proxy más
    cercano al cliente), nunca la primera. Con 0 se usa siempre la IP del socket."""
    global _warned_forwarded
    peer = _valid_ip(request.client.host) if request.client else None
    proxies = settings.TRUSTED_PROXY_COUNT
    forwarded = request.headers.get("x-forwarded-for")

    if proxies <= 0:
        if forwarded and not _warned_forwarded:
            _warned_forwarded = True
            logger.warning(
                "Llegan peticiones con X-Forwarded-For pero TRUSTED_PROXY_COUNT=0: los límites de ritmo y la "
                "auditoría usan la IP del proxy (%s), compartida por todos los usuarios. Detrás de Railway "
                "configurá TRUSTED_PROXY_COUNT=1.", peer,
            )
        return peer
    if not forwarded:
        return peer

    hops = [h.strip() for h in forwarded.split(",") if h.strip()]
    if len(hops) < proxies:
        return peer
    return _valid_ip(hops[-proxies]) or peer


def rate_limit_key(request: Request) -> str:
    """Clave para los límites de ritmo. Un cliente IPv6 suele tener un /64 entero y puede rotar direcciones dentro
    de él: contar por dirección no limitaría nada, así que las IPv6 se agrupan por /64."""
    ip = client_ip(request)
    if ip is None:
        return "unknown"
    address = ipaddress.ip_address(ip)
    if address.version == 6:
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return ip


def _valid_ip(text: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None
