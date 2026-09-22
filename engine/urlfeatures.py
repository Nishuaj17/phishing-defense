"""Stage 1 features: everything that can be learned from the address string alone.
 
Pure functions, no network access. That is what makes Stage 1 cheap enough to run
on every link.
"""
from __future__ import annotations
 
import ipaddress
import math
import re
from dataclasses import dataclass
from urllib.parse import urlsplit
 
from .brands import BRANDS, brands_in
 
try:  # optional: accurate public-suffix handling from the bundled snapshot (no network)
    import tldextract
 
    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True, cache_dir=None)
except Exception:  # pragma: no cover - fallback path is tested instead
    _EXTRACT = None
 
_TWO_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "ac.in", "gov.in", "org.in", "net.in",
    "nic.in", "edu.in", "res.in", "co.jp", "com.au", "net.au", "org.au", "co.nz", "co.za",
    "com.br", "com.cn", "com.sg", "com.mx", "com.tr", "com.pk", "com.bd", "com.np",
    "com.ng", "co.ke", "com.hk", "com.tw", "co.kr", "com.ua", "com.ar",
}
# Free hosting / tunnelling platforms. Treated as public suffixes so that
# "evil.github.io" is its own registered domain, and flagged as a feature.
FREE_HOSTING = {
    "github.io", "gitlab.io", "blogspot.com", "herokuapp.com", "vercel.app", "netlify.app",
    "web.app", "firebaseapp.com", "pages.dev", "workers.dev", "weebly.com", "wixsite.com",
    "000webhostapp.com", "glitch.me", "repl.co", "onrender.com", "surge.sh", "webflow.io",
    "carrd.co", "godaddysites.com", "framer.app", "duckdns.org", "ngrok.io",
    "ngrok-free.app", "trycloudflare.com",
}
_SUFFIXES2 = _TWO_LABEL_SUFFIXES | FREE_HOSTING
 
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rebrand.ly",
    "buff.ly", "shorturl.at", "rb.gy", "tiny.cc",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "country", "kim",
    "work", "support", "rest", "fit", "cam", "icu", "buzz", "cyou", "sbs", "quest",
    "monster", "lol",
}
SENSITIVE_WORDS = (
    "login", "signin", "sign-in", "verify", "secure", "account", "update", "confirm",
    "banking", "wallet", "otp", "password", "suspend", "unlock", "billing", "payment",
    "invoice", "refund", "kyc", "validate", "authenticate", "recover",
)
 
_NUMERIC_HOST = re.compile(r"^(0x[0-9a-f]+|\d{8,10})$", re.I)
 
 
def is_ip_host(host: str) -> bool:
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return bool(_NUMERIC_HOST.match(h))
 
 
def split_host(host: str) -> tuple[str, str, str]:
    """Return (subdomain, registered_domain, suffix)."""
    host = host.lower().strip(".")
    if not host or is_ip_host(host):
        return "", host, ""
    if _EXTRACT is not None:
        r = _EXTRACT(host)
        if r.suffix and r.domain:
            return r.subdomain, f"{r.domain}.{r.suffix}", r.suffix
        return "", host, r.suffix or ""
    labels = host.split(".")
    if len(labels) < 2:
        return "", host, ""
    n = 2 if ".".join(labels[-2:]) in _SUFFIXES2 else 1
    if len(labels) <= n:
        return "", host, host
    return (
        ".".join(labels[: -(n + 1)]),
        ".".join(labels[-(n + 1):]),
        ".".join(labels[-n:]),
    )
 
 
@dataclass(frozen=True)
class ParsedURL:
    url: str  # normalised, always has a scheme
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    has_userinfo: bool
    subdomain: str
    reg_domain: str
    suffix: str
 
 
def parse_url(url: str) -> ParsedURL:
    """Parse a user-supplied link. Raises ValueError if it cannot be a URL."""
    url = url.strip()
    if "://" not in url:
        url = "https://" + url.lstrip("/")
    sp = urlsplit(url)  # may raise ValueError (e.g. bad IPv6 literal)
    host = (sp.hostname or "").lower()
    if not host:
        raise ValueError("That doesn't look like a link.")
    try:
        port = sp.port
    except ValueError:
        raise ValueError("The link has an invalid port.") from None
    sub, reg, suffix = split_host(host)
    return ParsedURL(
        url=url,
        scheme=sp.scheme.lower(),
        host=host,
        port=port,
        path=sp.path,
        query=sp.query,
        has_userinfo="@" in sp.netloc,
        subdomain=sub,
        reg_domain=reg,
        suffix=suffix,
    )
 
 
def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())
 
 
def brand_findings(p: ParsedURL) -> dict[str, list[str]]:
    """Brands named in the address although the registered domain is not theirs."""
    if p.suffix and p.reg_domain.endswith("." + p.suffix):
        dom_label = p.reg_domain[: -(len(p.suffix) + 1)]
    else:
        dom_label = p.reg_domain
    out: dict[str, list[str]] = {"domain": [], "subdomain": [], "path": []}
    for key, text in (
        ("domain", dom_label),
        ("subdomain", p.subdomain),
        ("path", p.path + " " + p.query),
    ):
        for brand in sorted(brands_in(text)):
            if p.reg_domain not in BRANDS[brand]:
                out[key].append(brand)
    return out
 
 
FEATURE_NAMES = [
    "url_len", "host_len", "path_len", "query_len", "reg_domain_len", "longest_label_len",
    "n_dots_host", "n_subdomains", "n_hyphens_host", "n_digits_host", "digit_ratio_host",
    "host_entropy", "path_depth", "n_query_params", "n_percent_encoded",
    "has_ip_host", "has_at", "has_port_nonstd", "is_https", "has_punycode",
    "has_double_slash_path", "suspicious_tld", "is_shortener", "is_free_hosting",
    "n_sensitive_words", "brand_in_domain_mismatch", "brand_in_subdomain_mismatch",
    "brand_in_path_mismatch",
]
 
 
def extract_features(url: str) -> dict[str, float]:
    p = parse_url(url)
    host = p.host
    labels = host.split(".")
    digits = sum(ch.isdigit() for ch in host)
    lowered = (host + p.path + "?" + p.query).lower()
    subs = [s for s in p.subdomain.split(".") if s and s != "www"]
    brands = brand_findings(p)
    tld = p.suffix.split(".")[-1] if p.suffix else ""
    f = {
        "url_len": len(p.url),
        "host_len": len(host),
        "path_len": len(p.path),
        "query_len": len(p.query),
        "reg_domain_len": len(p.reg_domain),
        "longest_label_len": max(len(x) for x in labels),
        "n_dots_host": host.count("."),
        "n_subdomains": len(subs),
        "n_hyphens_host": host.count("-"),
        "n_digits_host": digits,
        "digit_ratio_host": digits / len(host),
        "host_entropy": _entropy(host),
        "path_depth": p.path.count("/"),
        "n_query_params": (p.query.count("&") + 1) if p.query else 0,
        "n_percent_encoded": len(re.findall(r"%[0-9a-fA-F]{2}", p.url)),
        "has_ip_host": is_ip_host(host),
        "has_at": p.has_userinfo,
        "has_port_nonstd": p.port not in (None, 80, 443),
        "is_https": p.scheme == "https",
        "has_punycode": "xn--" in host,
        "has_double_slash_path": "//" in p.path,
        "suspicious_tld": tld in SUSPICIOUS_TLDS,
        "is_shortener": p.reg_domain in SHORTENERS,
        "is_free_hosting": any(host == s or host.endswith("." + s) for s in FREE_HOSTING),
        "n_sensitive_words": sum(1 for w in SENSITIVE_WORDS if w in lowered),
        "brand_in_domain_mismatch": bool(brands["domain"]),
        "brand_in_subdomain_mismatch": bool(brands["subdomain"]),
        "brand_in_path_mismatch": bool(brands["path"]),
    }
    return {k: float(v) for k, v in f.items()}
 
 
def feature_vector(url: str) -> list[float]:
    f = extract_features(url)
    return [f[name] for name in FEATURE_NAMES]
 
