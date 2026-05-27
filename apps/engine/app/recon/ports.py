import asyncio
import logging
from typing import Optional

from pydantic import BaseModel

from app.recon.port_lists import FULL, TOP_100, TOP_1000

logger = logging.getLogger(__name__)

SEMAPHORE_LIMIT = 200
BANNER_TIMEOUT = 2.0
BANNER_READ_BYTES = 1024

# Static service inference — no dynamic lookup
KNOWN_SERVICES: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    514: "syslog",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm-http",
    5986: "winrm-https",
    6379: "redis",
    6443: "kubernetes-api",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9200: "elasticsearch",
    9300: "elasticsearch-transport",
    11211: "memcached",
    27017: "mongodb",
    27018: "mongodb-shard",
}


class PortResult(BaseModel):
    host: str
    port: int
    protocol: str = "tcp"
    state: str
    service: Optional[str] = None
    banner: Optional[str] = None


def _ports_for_range(port_range: str) -> list[int]:
    if port_range == "top-100":
        return TOP_100
    if port_range == "full":
        return list(FULL)
    return TOP_1000  # default: top-1000


async def _probe(
    sem: asyncio.Semaphore,
    host: str,
    port: int,
    timeout: float,
) -> PortResult:
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return PortResult(host=host, port=port, state="closed")

        banner: Optional[str] = None
        try:
            data = await asyncio.wait_for(
                reader.read(BANNER_READ_BYTES),
                timeout=BANNER_TIMEOUT,
            )
            if data:
                banner = data.decode("utf-8", errors="replace").strip()[:500]
        except Exception:
            pass

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        return PortResult(
            host=host,
            port=port,
            state="open",
            service=KNOWN_SERVICES.get(port),
            banner=banner,
        )


async def scan_ports(
    host: str,
    port_range: str,
    timeout: float,
) -> list[PortResult]:
    ports = _ports_for_range(port_range)
    sem = asyncio.Semaphore(SEMAPHORE_LIMIT)
    results = await asyncio.gather(*[_probe(sem, host, p, timeout) for p in ports])
    return [r for r in results if r.state == "open"]
