"""
Passive subdomain enumeration via crt.sh certificate transparency logs.

Only source in Phase 1: crt_sh.
DNS brute-force (active) is gated behind domain verification and goes in a
later phase.
"""
import asyncio
import ipaddress
import json
import logging
import re
from typing import Optional

import dns.asyncresolver
import dns.exception
import httpx
from pydantic import BaseModel

from app.recon.netguard import allow_private_targets, is_public_ip

logger = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/?q=%.{domain}&output=json"
CRTSH_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
CRTSH_MAX_BYTES = 25 * 1024 * 1024  # un dominio con millones de certificados no puede agotar la memoria del motor
DNS_CONCURRENCY = 50  # max parallel A-record lookups
MAX_A_RECORDS = 10

# Solo nombres de host reales: los certificados pueden traer cualquier cosa y el nombre termina en una URL.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")


class CrtShTooLarge(Exception):
    """crt.sh devolvió más datos de los que el motor acepta para un solo dominio."""


class SubdomainResult(BaseModel):
    hostname: str
    source: str = "crt_sh"
    resolved_ip: Optional[str] = None
    # Si el nombre resuelve a una dirección que no es pública: no se guarda la dirección y no se escanea (ver netguard).
    skipped_reason: Optional[str] = None


async def _resolve_a(hostname: str) -> list[str]:
    """Best-effort A record lookup. Returns [] on any failure."""
    try:
        answers = await dns.asyncresolver.resolve(hostname, "A")
        return [str(a) for a in list(answers)[:MAX_A_RECORDS]]
    except (dns.exception.DNSException, Exception):
        return []


def _classify(hostname: str, addresses: list[str]) -> SubdomainResult:
    """Una respuesta DNS con alguna dirección no pública (loopback, red interna, metadatos de la nube) se descarta
    entera: el nombre queda sin IP y marcado, para que el escaneo no se conecte ahí."""
    if not addresses:
        return SubdomainResult(hostname=hostname)
    if not allow_private_targets() and not all(is_public_ip(ipaddress.ip_address(a)) for a in addresses):
        return SubdomainResult(hostname=hostname, skipped_reason="non_public_address")
    return SubdomainResult(hostname=hostname, resolved_ip=addresses[0])


async def _fetch_crtsh(domain: str) -> set[str]:
    """
    Fetches certificate transparency entries for %.{domain} from crt.sh.
    Raises httpx.HTTPStatusError on non-2xx, httpx.RequestError on network failure, CrtShTooLarge if the answer
    is huge. All of them bubble up to the caller (scan_runner marks job as failed).
    """
    url = CRTSH_URL.format(domain=domain)
    # crt.sh es un destino fijo (no lo elige el usuario): no pasa por la guarda de red ni sigue redirecciones.
    async with httpx.AsyncClient(timeout=CRTSH_TIMEOUT, follow_redirects=False) as client:
        async with client.stream("GET", url, headers={"Accept": "application/json"}) as resp:
            resp.raise_for_status()
            raw = bytearray()
            async for chunk in resp.aiter_bytes():
                raw += chunk
                if len(raw) > CRTSH_MAX_BYTES:
                    raise CrtShTooLarge(domain)
    entries = json.loads(raw)

    hostnames: set[str] = set()
    for entry in entries if isinstance(entries, list) else []:
        names = entry.get("name_value") if isinstance(entry, dict) else None
        if not isinstance(names, str):
            continue
        for raw_name in names.split("\n"):
            name = raw_name.strip().lower()
            if not name:
                continue
            # Strip wildcard prefix — keep the base name
            if name.startswith("*."):
                name = name[2:]
            # Only accept valid subdomains (or the apex itself)
            if (name == domain or name.endswith(f".{domain}")) and _HOSTNAME_RE.match(name):
                hostnames.add(name)

    logger.info("crt.sh returned %d unique hostnames for %s", len(hostnames), domain)
    return hostnames


async def enumerate_subdomains(domain: str) -> list[SubdomainResult]:
    """
    Entry point for the Phase 1 subdomain module.

    1. Fetches hostnames from crt.sh (raises on HTTP/network error).
    2. Resolves A records concurrently (best-effort; non-resolving → resolved_ip=None).

    Returns a deduplicated list of SubdomainResult.
    """
    hostnames = await _fetch_crtsh(domain)

    if not hostnames:
        return []

    semaphore = asyncio.Semaphore(DNS_CONCURRENCY)

    async def _resolve_bounded(h: str) -> SubdomainResult:
        async with semaphore:
            addresses = await _resolve_a(h)
        return _classify(h, addresses)

    results = await asyncio.gather(*[_resolve_bounded(h) for h in sorted(hostnames)])
    return list(results)
