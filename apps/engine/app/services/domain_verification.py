import httpx
import dns.asyncresolver
import dns.exception

_FETCH_TIMEOUT = 8.0  # seconds


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


async def verify_well_known_file(domain: str, token: str) -> bool:
    """
    Fetches https://<domain>/.well-known/recon-verification.txt and checks
    that the body equals token exactly.  Returns False on any HTTP/network error.
    """
    url = f"https://{domain}/.well-known/recon-verification.txt"
    try:
        async with httpx.AsyncClient(
            timeout=_FETCH_TIMEOUT,
            follow_redirects=True,
        ) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                return resp.text.strip() == token
    except Exception:
        pass
    return False
