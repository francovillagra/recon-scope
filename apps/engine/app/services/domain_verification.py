from datetime import datetime, timedelta, timezone
from typing import Optional

import dns.asyncresolver
import dns.exception
import httpx

from app.config import settings
from app.recon.netguard import BlockedTarget
from app.recon.safe_http import fetch_in_scope

_FETCH_TIMEOUT = 8.0  # seconds
_TOKEN_MAX_BYTES = 4096  # el archivo solo contiene el token: un cuerpo más grande no puede ser el token


def verification_expired(domain) -> bool:
    """¿Venció la verificación? Con VERIFICATION_MAX_AGE_DAYS=0 (por defecto) nunca vence. Un dominio puede cambiar
    de manos después de verificarse: pasado el plazo hay que volver a demostrar el control."""
    days = settings.VERIFICATION_MAX_AGE_DAYS
    if days <= 0:
        return False
    if domain.verified_at is None:
        return True
    return domain.verified_at < datetime.now(timezone.utc) - timedelta(days=days)


async def verify_dns_txt(domain: str, token: str) -> bool:
    """
    Resolves TXT records at _recon-verify.<domain> and checks for an exact
    match of token.  Returns False (not an exception) on any DNS error.
    """
    record_name = f"_recon-verify.{domain}"
    try:
        answers = await dns.asyncresolver.resolve(record_name, "TXT")
        for rdata in answers:
            for string in rdata.strings:
                if string.decode("utf-8").strip() == token:
                    return True
    except (dns.exception.DNSException, Exception):
        pass
    return False


async def verify_well_known_file(
    domain: str, token: str, *, transport: Optional[httpx.AsyncBaseTransport] = None
) -> bool:
    """
    Fetches https://<domain>/.well-known/recon-verification.txt and checks
    that the body equals token exactly.  Returns False on any HTTP/network error.

    Lanza `BlockedTarget` si el dominio resuelve a una dirección que no es pública: el motor no se conecta ahí
    (ver netguard). Las redirecciones solo se siguen dentro del propio dominio y sin bajar de https a http, así
    el archivo tiene que estar publicado por quien controla ese dominio y no en un sitio ajeno al que apunte.
    `transport` solo se pasa en las pruebas.
    """
    url = f"https://{domain}/.well-known/recon-verification.txt"
    try:
        fetched = await fetch_in_scope(
            url,
            scope=domain,
            timeout=_FETCH_TIMEOUT,
            max_body_bytes=_TOKEN_MAX_BYTES,
            transport=transport,
        )
    except BlockedTarget:
        raise
    except Exception:
        return False
    if fetched.status_code != 200 or fetched.not_followed or fetched.truncated:
        return False
    return fetched.text.strip() == token
