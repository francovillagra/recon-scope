import asyncio
import re
import ssl
from datetime import datetime, timezone
from typing import Optional

import httpx
from pydantic import BaseModel

_TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,256})</title>", re.IGNORECASE)
_VERSION_RE = re.compile(r"\d+[\.\d]+")


# ── Result models ─────────────────────────────────────────────────────────────

class HttpFingerprintResult(BaseModel):
    url: str
    status_code: Optional[int] = None
    server_header: Optional[str] = None
    title: Optional[str] = None
    response_headers: dict = {}


class TechResult(BaseModel):
    name: str
    category: str
    version: Optional[str] = None
    confidence: int  # 0–100


class TlsResult(BaseModel):
    host: str
    issuer: Optional[str] = None
    subject: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    is_valid: Optional[bool] = None
    signature_algorithm: Optional[str] = None
    san: list[str] = []


# ── HTTP fingerprinting ───────────────────────────────────────────────────────

async def fingerprint_http(url: str, timeout: float) -> Optional[HttpFingerprintResult]:
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            max_redirects=3,
            timeout=timeout,
            verify=False,  # capture even sites with bad certs
        ) as client:
            resp = await client.get(url)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            server = headers_lower.get("server")
            title_match = _TITLE_RE.search(resp.text[:8192])
            title = title_match.group(1).strip() if title_match else None
            return HttpFingerprintResult(
                url=str(resp.url),
                status_code=resp.status_code,
                server_header=server,
                title=title,
                response_headers=dict(resp.headers),
            )
    except Exception:
        return None


# ── Technology detection ──────────────────────────────────────────────────────

_SERVER_MAP: list[tuple[str, str, str]] = [
    # (header substring, tech name, category)
    ("nginx", "nginx", "web-server"),
    ("apache", "Apache", "web-server"),
    ("microsoft-iis", "IIS", "web-server"),
    ("iis", "IIS", "web-server"),
    ("caddy", "Caddy", "web-server"),
    ("cloudflare", "Cloudflare", "cdn"),
    ("lighttpd", "lighttpd", "web-server"),
    ("gunicorn", "Gunicorn", "web-server"),
    ("uvicorn", "Uvicorn", "web-server"),
]

_POWERED_BY_MAP: list[tuple[str, str, str]] = [
    ("php", "PHP", "language"),
    ("express", "Express", "framework"),
    ("asp.net", "ASP.NET", "framework"),
    ("next.js", "Next.js", "framework"),
    ("django", "Django", "framework"),
]

_TITLE_PATTERNS: list[tuple[str, str, str]] = [
    ("wordpress", "WordPress", "cms"),
    ("drupal", "Drupal", "cms"),
    ("joomla", "Joomla", "cms"),
    ("ghost", "Ghost", "cms"),
    ("shopify", "Shopify", "ecommerce"),
]

_COOKIE_MAP: list[tuple[str, str, str]] = [
    ("laravel_session", "Laravel", "framework"),
    ("csrftoken", "Django", "framework"),
    ("_session_id", "Rails", "framework"),
]


async def detect_technologies(fp: HttpFingerprintResult) -> list[TechResult]:
    results: list[TechResult] = []
    h = {k.lower(): v.lower() for k, v in fp.response_headers.items()}
    seen: set[str] = set()

    def add(name: str, category: str, version: Optional[str], confidence: int) -> None:
        if name not in seen:
            seen.add(name)
            results.append(TechResult(name=name, category=category, version=version, confidence=confidence))

    server = h.get("server", "")
    for substr, name, cat in _SERVER_MAP:
        if substr in server:
            vm = _VERSION_RE.search(server)
            add(name, cat, vm.group(0) if vm else None, 90)
            break

    powered = h.get("x-powered-by", "")
    for substr, name, cat in _POWERED_BY_MAP:
        if substr in powered:
            vm = _VERSION_RE.search(powered)
            add(name, cat, vm.group(0) if vm else None, 90)
            break

    # CDN / cloud
    if "cf-ray" in h or "cloudflare" in server:
        add("Cloudflare", "cdn", None, 95)
    if any(k.startswith("x-vercel-") for k in h):
        add("Vercel", "hosting", None, 95)
    if any(k.startswith("x-amz-") for k in h) or "amazonaws" in h.get("server", ""):
        add("AWS", "cloud", None, 85)

    # Cookie-based
    set_cookie = h.get("set-cookie", "")
    for cookie_key, name, cat in _COOKIE_MAP:
        if cookie_key in set_cookie:
            add(name, cat, None, 80)
    if "wordpress_" in set_cookie or "wp-settings-" in set_cookie:
        add("WordPress", "cms", None, 85)

    # Title patterns
    if fp.title:
        t = fp.title.lower()
        for pattern, name, cat in _TITLE_PATTERNS:
            if pattern in t:
                add(name, cat, None, 70)

    return results


# ── TLS fingerprinting ────────────────────────────────────────────────────────

_CERT_DATE_FMT = "%b %d %H:%M:%S %Y %Z"


def _parse_cert_date(s: str) -> Optional[datetime]:
    try:
        return datetime.strptime(s, _CERT_DATE_FMT).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _cert_to_tls_result(host: str, cert: dict, is_valid: bool) -> TlsResult:
    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))
    valid_from = _parse_cert_date(cert.get("notBefore", ""))
    valid_to = _parse_cert_date(cert.get("notAfter", ""))
    now = datetime.now(timezone.utc)
    # If chain/hostname valid, additionally check expiry
    if is_valid and valid_to:
        is_valid = valid_to > now
    san = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
    return TlsResult(
        host=host,
        issuer=issuer.get("organizationName") or issuer.get("commonName"),
        subject=subject.get("commonName"),
        valid_from=valid_from,
        valid_to=valid_to,
        is_valid=is_valid,
        signature_algorithm=None,  # not exposed by ssl.getpeercert()
        san=san,
    )


async def fingerprint_tls(host: str, timeout: float) -> Optional[TlsResult]:
    # ── try with full validation first ───────────────────────────────────────
    ctx_valid = ssl.create_default_context()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, 443, ssl=ctx_valid),
            timeout=timeout,
        )
        ssl_obj = writer.get_extra_info("ssl_object")
        cert = ssl_obj.getpeercert()
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return _cert_to_tls_result(host, cert or {}, is_valid=True)

    except ssl.SSLCertVerificationError:
        # Cert present but invalid chain/hostname — reconnect without verification
        ctx_noverify = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_noverify.check_hostname = False
        ctx_noverify.verify_mode = ssl.CERT_NONE
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 443, ssl=ctx_noverify),
                timeout=timeout,
            )
            ssl_obj = writer.get_extra_info("ssl_object")
            cert = ssl_obj.getpeercert()
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return _cert_to_tls_result(host, cert or {}, is_valid=False)
        except Exception:
            return TlsResult(host=host, is_valid=False)

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None  # port 443 not reachable — no TLS to report
    except Exception:
        return None
