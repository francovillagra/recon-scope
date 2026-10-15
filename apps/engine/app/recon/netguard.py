"""
Guarda contra SSRF: el motor solo se conecta a direcciones de Internet pública.

Por qué hace falta
------------------
El permiso para escanear se concede por NOMBRE de dominio (registro TXT o archivo .well-known), pero el motor
abre las conexiones contra DIRECCIONES IP. Quien controla el DNS de su dominio decide a qué IP apunta cada
nombre, así que sin esta guarda un dominio "verificado" puede apuntar a 127.0.0.1, 10.x.x.x o 169.254.169.254
(metadatos de la nube) y usar al motor para mirar su propia red, con los banners, títulos y cabeceras devueltos
en el informe.

Cómo funciona
-------------
1. `resolve_public()` resuelve el nombre UNA vez y devuelve solo direcciones públicas. Si alguna de las
   respuestas no lo es, lanza `BlockedTarget`: una respuesta mixta (una pública y una interna) es una técnica
   clásica para colarse cuando el cliente "prueba la siguiente dirección".
2. Quien se conecta usa ESA dirección y no vuelve a resolver el nombre. Así un DNS que contesta distinto la
   segunda vez ("DNS rebinding") no puede cambiar el destino después de la validación.
3. Se miran las formas que esconden un IPv4 dentro de un IPv6 (::ffff:127.0.0.1, 64:ff9b::7f00:1, 2002:7f00:1::)
   y las que `getaddrinfo` acepta como IPv4 (2130706433, 0x7f.1, 127.1): se juzga la dirección ya resuelta,
   no el texto.

`ALLOW_PRIVATE_TARGETS=true` apaga la guarda. Es solo para desarrollo o para quien despliega el motor dentro
de su propia red; en un servicio compartido tiene que quedar en false.
"""
import asyncio
import ipaddress
import socket
import ssl
from typing import Optional, Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

_GLOBAL_UNICAST_V6 = ipaddress.ip_network("2000::/3")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")  # RFC 6052: IPv4 embebido en los últimos 32 bits
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")


class BlockedTarget(Exception):
    """El destino no es una dirección pública de Internet: el motor no se conecta."""

    def __init__(self, host: str, reason: str = "non_public_address") -> None:
        super().__init__(f"{host}: {reason}")
        self.host = host
        self.reason = reason


def is_public_ip(ip: IPAddress) -> bool:
    """True solo para direcciones alcanzables desde Internet pública.

    No depende de `ipaddress.is_global` por sí sola: su resultado cambió entre versiones de Python (las
    direcciones IPv4 mapeadas en IPv6 y los rangos multicast, por ejemplo)."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return is_public_ip(ip.ipv4_mapped)
        if ip in _NAT64:
            return is_public_ip(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        # Lista de permitidos: solo el unicast global (2000::/3). Deja fuera ::/8, fc00::/7, fe80::/10, ff00::/8...
        if ip not in _GLOBAL_UNICAST_V6 or ip in _SIX_TO_FOUR:
            return False
    return bool(ip.is_global) and not (
        ip.is_multicast or ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved or ip.is_unspecified
    )


def _as_ip(host: str) -> Optional[IPAddress]:
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        return ipaddress.ip_address(candidate.split("%", 1)[0])
    except ValueError:
        return None


async def _lookup(host: str, port: int) -> list[str]:
    """Resolución del sistema (la misma que usaría el cliente). Aparte para poder reemplazarla en las pruebas."""
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


def allow_private_targets(override: Optional[bool] = None) -> bool:
    """¿Está apagada la guarda? (`ALLOW_PRIVATE_TARGETS`). `override` lo usan las pruebas."""
    if override is not None:
        return override
    from app.config import settings  # import tardío: el módulo se puede importar sin configuración

    return settings.ALLOW_PRIVATE_TARGETS


async def resolve_public(host: str, port: int = 0, *, allow_private: Optional[bool] = None) -> list[str]:
    """Resuelve `host` y devuelve sus direcciones (IPv4 primero), todas públicas.

    - Lanza `BlockedTarget` si CUALQUIER respuesta no es pública.
    - Un nombre que no resuelve lanza `socket.gaierror` (un `OSError`), igual que al conectarse.
    """
    allow = allow_private_targets(allow_private)
    literal = _as_ip(host)
    raw = [str(literal)] if literal is not None else await _lookup(host, port)

    addresses: list[IPAddress] = []
    for text in raw:
        ip = ipaddress.ip_address(text.split("%", 1)[0])
        if not allow and not is_public_ip(ip):
            raise BlockedTarget(host)
        if ip not in addresses:
            addresses.append(ip)
    if not addresses:
        raise socket.gaierror(socket.EAI_NONAME, "the name has no addresses")
    # IPv4 primero: un contenedor sin ruta IPv6 fallaría con la primera dirección de un host de doble pila.
    addresses.sort(key=lambda ip: ip.version)
    return [str(ip) for ip in addresses]


async def connect_any(
    addresses: list[str],
    port: int,
    timeout: float,
    *,
    ssl_context: Optional[ssl.SSLContext] = None,
    server_hostname: Optional[str] = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Abre una conexión a la primera dirección que responda. Recibe direcciones YA validadas: no resuelve nada.

    Con TLS, `server_hostname` es el nombre del dominio: se usa para SNI y para verificar el certificado."""
    last: Optional[BaseException] = None
    for address in addresses:
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(address, port, ssl=ssl_context, server_hostname=server_hostname),
                timeout=timeout,
            )
        except ssl.SSLError:
            raise  # el servidor respondió: probar otra dirección no cambia el veredicto del certificado
        except (asyncio.TimeoutError, OSError) as exc:
            last = exc
    raise last if last is not None else ConnectionRefusedError("no addresses to connect to")
