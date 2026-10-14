"""
Cliente HTTP para tocar sitios de terceros sin dejar que el destino decida adónde va el motor.

Dos controles, los dos aplicados en cada salto de una redirección:

1. Conexión: `GuardedBackend` resuelve el nombre, exige que TODAS las respuestas sean públicas (ver
   `netguard`) y conecta a esa dirección, sin volver a resolver. El nombre sigue siendo el de la URL para el
   encabezado Host, el SNI y la verificación del certificado.
2. Alcance: el permiso se verificó para un dominio, así que las redirecciones solo se siguen dentro de ese dominio
   y sus subdominios, y nunca de https a http. Una redirección que sale de ahí no se sigue: se devuelve la
   respuesta 3xx tal cual, que ya dice adónde mandaba.
"""
import asyncio
from dataclasses import dataclass
from typing import Optional

import httpcore
import httpx

from app.recon.netguard import BlockedTarget, resolve_public

MAX_BODY_BYTES = 64 * 1024  # de una página solo hace falta el principio (el <title>); no se baja el resto
MAX_REDIRECTS = 3


class GuardedBackend(httpcore.AsyncNetworkBackend):
    """Backend de red de httpcore que solo abre conexiones hacia direcciones públicas ya validadas."""

    def __init__(self, inner: httpcore.AsyncNetworkBackend) -> None:
        self._inner = inner

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        try:
            addresses = await asyncio.wait_for(resolve_public(host, port), timeout)
        except asyncio.TimeoutError as exc:
            raise httpcore.ConnectTimeout(f"timed out resolving {host}") from exc
        except OSError as exc:  # el nombre no resuelve
            raise httpcore.ConnectError(f"cannot resolve {host}") from exc
        # BlockedTarget no se captura: sube tal cual hasta quien llamó a httpx.

        last: Optional[Exception] = None
        for address in addresses:
            try:
                return await self._inner.connect_tcp(
                    address, port, timeout=timeout, local_address=local_address, socket_options=socket_options
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last = exc
        raise last  # type: ignore[misc]  # addresses nunca está vacío: resolve_public lo garantiza

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise BlockedTarget(path, "unix_socket")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def guarded_transport(
    *, verify: bool = True, backend: Optional[httpcore.AsyncNetworkBackend] = None
) -> httpx.AsyncHTTPTransport:
    """Transporte de httpx cuyas conexiones pasan por `GuardedBackend`.

    httpx no expone el backend de red, así que se reemplaza el atributo del pool de httpcore. Si una versión
    nueva lo renombra, esto falla al construirse (no en silencio) y la prueba de conexión real lo detecta."""
    transport = httpx.AsyncHTTPTransport(verify=verify, retries=0)
    pool = getattr(transport, "_pool", None)
    if pool is None or not hasattr(pool, "_network_backend"):
        raise RuntimeError("httpx/httpcore cambiaron su estructura interna: no se puede instalar la guarda de red")
    pool._network_backend = GuardedBackend(backend or pool._network_backend)
    return transport


@dataclass
class Fetched:
    url: str  # URL de la última respuesta recibida
    status_code: int
    headers: httpx.Headers
    body: bytes  # como mucho `max_body_bytes`
    truncated: bool
    not_followed: Optional[str] = None  # por qué no se siguió la redirección que traía (código, sin direcciones)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def in_scope(host: str, scope: str) -> bool:
    host, scope = host.lower().rstrip("."), scope.lower().rstrip(".")
    return host == scope or host.endswith("." + scope)


def _redirect_refusal(current: httpx.URL, target: httpx.URL, scope: str) -> Optional[str]:
    if target.scheme not in ("http", "https"):
        return "unsupported_scheme"
    if current.scheme == "https" and target.scheme == "http":
        return "https_downgrade"
    if not in_scope(target.raw_host.decode("ascii"), scope):
        return "out_of_scope"
    return None


async def _get(client: httpx.AsyncClient, url: str, max_bytes: int) -> tuple[Fetched, Optional[httpx.URL]]:
    async with client.stream("GET", url) as resp:
        body = bytearray()
        truncated = False
        async for chunk in resp.aiter_bytes():
            body += chunk
            if len(body) > max_bytes:
                del body[max_bytes:]
                truncated = True
                break  # al salir se cierra la conexión sin bajar el resto
        fetched = Fetched(str(resp.url), resp.status_code, resp.headers, bytes(body), truncated)
        return fetched, (resp.next_request.url if resp.next_request is not None else None)


async def fetch_in_scope(
    url: str,
    *,
    scope: str,
    timeout: float,
    verify_tls: bool = True,
    max_redirects: int = MAX_REDIRECTS,
    max_body_bytes: int = MAX_BODY_BYTES,
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> Fetched:
    """GET con las dos guardas. Lanza `BlockedTarget` si el primer destino no es público; cualquier otro
    problema de red sale como excepción de httpx. `transport` solo se pasa en las pruebas."""
    async with httpx.AsyncClient(
        transport=transport or guarded_transport(verify=verify_tls),
        timeout=timeout,
        follow_redirects=False,
        headers={"Accept-Encoding": "identity"},  # sin compresión: nada que descomprimir de un servidor hostil
    ) as client:
        # Tope de tiempo total: los timeouts de httpx son por operación y un servidor que gotea bytes los renueva.
        async with asyncio.timeout(max(timeout, 1.0) * 2):
            current = url
            previous: Optional[Fetched] = None
            for hop in range(max_redirects + 1):
                try:
                    fetched, target = await _get(client, current, max_body_bytes)
                except BlockedTarget:
                    if previous is None:
                        raise
                    previous.not_followed = "redirect_target_not_public"
                    return previous
                if target is None:
                    return fetched
                refusal = _redirect_refusal(httpx.URL(current), target, scope)
                if refusal is None and hop == max_redirects:
                    refusal = "too_many_redirects"
                if refusal is not None:
                    fetched.not_followed = refusal
                    return fetched
                previous, current = fetched, str(target)
            raise AssertionError("unreachable")  # pragma: no cover
