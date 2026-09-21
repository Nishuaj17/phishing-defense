"""Fetch a user-supplied URL without letting it reach our own network.

This is the riskiest code in the project: it makes HTTP requests to addresses that
strangers choose. Guards implemented here:

* http/https only, ports 80/443 only, no credentials in the URL
* every resolved address must be globally routable (blocks loopback, private
  ranges, link-local/cloud metadata 169.254.169.254, IPv4-mapped IPv6, etc.)
* redirects are followed manually and each hop is re-validated
* hard limits on time, redirects and bytes; HTML content types only
* no JavaScript is ever executed and no cookies are kept

Known gap: DNS rebinding between validation and connection is not fully closed.
In production, run this in a container/VM whose network policy only allows
outbound internet and blocks your internal ranges.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import requests
import urllib3

MAX_BYTES = 1_500_000
MAX_REDIRECTS = 4
TOTAL_TIMEOUT = 12.0
ALLOWED_PORTS = {None, 80, 443}
USER_AGENT = "Mozilla/5.0 (compatible; PhishDefenseResearchBot/0.1)"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class BlockedURL(ValueError):
    """The URL must not be fetched."""


@dataclass
class FetchResult:
    ok: bool
    final_url: str | None = None
    status: int | None = None
    html: str = ""
    error: str = ""
    blocked: bool = False
    tls_error: bool = False
    redirects: int = 0
    ms: float = 0.0


def _ip_ok(addr: str) -> bool:
    ip = ipaddress.ip_address(addr.split("%")[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def validate_url(url: str) -> str:
    """Return the URL if it is safe to fetch, else raise BlockedURL."""
    sp = urlsplit(url)
    if sp.scheme not in ("http", "https"):
        raise BlockedURL("Only http and https links can be opened.")
    host = sp.hostname
    if not host:
        raise BlockedURL("The link has no host name.")
    if sp.username or sp.password:
        raise BlockedURL("Links with embedded credentials are not opened.")
    try:
        port = sp.port
    except ValueError:
        raise BlockedURL("The link has an invalid port.") from None
    if port not in ALLOWED_PORTS:
        raise BlockedURL("Only the standard web ports are opened.")
    try:
        ipaddress.ip_address(host)
        addrs = [host]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, port or (443 if sp.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            raise BlockedURL("The domain does not resolve.") from None
        addrs = sorted({i[4][0] for i in infos})
    if not addrs or not all(_ip_ok(a) for a in addrs):
        raise BlockedURL("The address is not on the public internet, so it was not opened.")
    return url


def fetch_page(url: str) -> FetchResult:
    started = time.monotonic()
    session = requests.Session()
    session.trust_env = False  # ignore proxy env vars and .netrc
    current = url
    tls_error = False

    def done(**kw) -> FetchResult:
        return FetchResult(ms=(time.monotonic() - started) * 1000, tls_error=tls_error, **kw)

    for hop in range(MAX_REDIRECTS + 1):
        if time.monotonic() - started > TOTAL_TIMEOUT:
            return done(ok=False, error="The page took too long to respond.", redirects=hop)
        try:
            current = validate_url(current)
        except BlockedURL as e:
            return done(ok=False, error=str(e), blocked=True, redirects=hop)
        try:
            try:
                r = session.get(current, headers={"User-Agent": USER_AGENT}, timeout=(3.05, 6),
                                allow_redirects=False, stream=True)
            except requests.exceptions.SSLError:
                tls_error = True  # phishing hosts often have bad certificates; we only read
                r = session.get(current, headers={"User-Agent": USER_AGENT}, timeout=(3.05, 6),
                                allow_redirects=False, stream=True, verify=False)
        except requests.RequestException as e:
            return done(ok=False, error=f"Could not connect ({type(e).__name__}).", redirects=hop)

        if r.is_redirect and r.headers.get("location"):
            nxt = urljoin(current, r.headers["location"])
            r.close()
            current = nxt
            continue

        ctype = r.headers.get("content-type", "").lower()
        if ctype and "html" not in ctype and "xml" not in ctype:
            r.close()
            return done(ok=False, final_url=current, status=r.status_code,
                        error="The address does not serve a web page.", redirects=hop)
        body = bytearray()
        try:
            for chunk in r.iter_content(16384):
                body += chunk
                if len(body) > MAX_BYTES or time.monotonic() - started > TOTAL_TIMEOUT:
                    break
        except requests.RequestException as e:
            r.close()
            return done(ok=False, error=f"Connection dropped ({type(e).__name__}).", redirects=hop)
        r.close()
        try:
            html = bytes(body).decode(r.encoding or "utf-8", errors="replace")
        except LookupError:
            html = bytes(body).decode("utf-8", errors="replace")
        return done(ok=True, final_url=current, status=r.status_code, html=html, redirects=hop)

    return done(ok=False, error="Too many redirects.", redirects=MAX_REDIRECTS)
