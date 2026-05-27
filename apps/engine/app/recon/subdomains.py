"""
Passive subdomain enumeration via crt.sh certificate transparency logs.

Only source in Phase 1: crt_sh.
DNS brute-force (active) is gated behind domain verification and goes in a
later phase.
"""
import asyncio
import logging
from typing import Optional

import dns.asyncresolver
import dns.exception
import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/?q=%.{domain}&output=json"
CRTSH_TIMEOUT = 30.0
DNS_CONCURRENCY = 50  # max parallel A-record lookups


class SubdomainResult(BaseModel):
    hostname: str
    source: str = "crt_sh"
    resolved_ip: Optional[str] = None


async def _resolve_a(hostname: str) -> Optional[str]:
    """Best-effort A record lookup. Returns None on any failure."""
    try:
        answers = await dns.asyncresolver.resolve(hostname, "A")
        return str(answers[0])
    except (dns.exception.DNSException, Exception):
        return None


async def _fetch_crtsh(domain: str) -> set[str]:
    """
    Fetches certificate transparency entries for %.{domain} from crt.sh.
    Raises httpx.HTTPStatusError on non-2xx, httpx.RequestError on network failure.
    Both bubble up to the caller (scan_runner marks job as failed).
    """
    url = CRTSH_URL.format(domain=domain)
    async with httpx.AsyncClient(timeout=CRTSH_TIMEOUT, follow_redirects=True) as client:
        resp = await client.get(url, headers={"Accept": "application/json"})
        resp.raise_for_status()
        entries = resp.json()

    hostnames: set[str] = set()
    for entry in entries:
        for raw in entry.get("name_value", "").split("\n"):
            name = raw.strip().lower()
            if not name:
                continue
            # Strip wildcard prefix — keep the base name
            if name.startswith("*."):
                name = name[2:]
            # Only accept valid subdomains (or the apex itself)
            if name == domain or name.endswith(f".{domain}"):
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
            ip = await _resolve_a(h)
        return SubdomainResult(hostname=h, resolved_ip=ip)

    results = await asyncio.gather(*[_resolve_bounded(h) for h in hostnames])
    return list(results)
