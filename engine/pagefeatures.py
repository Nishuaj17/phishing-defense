"""Stage 2: static analysis of the page's HTML. Never executes JavaScript.

`analyze_page` is a pure function of (html, url), so it can be run offline over a
saved dataset for the experiments as well as live in the API.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from .brands import BRANDS, brands_in
from .types import Evidence
from .urlfeatures import parse_url, split_host

PAGE_VERSION = "page-heuristic-v1"
MAX_HTML = 1_500_000
BIAS = -3.0

_CRED_NAME = re.compile(
    r"(otp|cvv|cvc|card|\bpin\b|mpin|aadhaar|aadhar|\bpan\b|ssn|passcode|security.?code|expiry)", re.I
)
_URGENT = (
    "verify your account", "account has been suspended", "account will be suspended",
    "confirm your identity", "unusual activity", "unusual sign-in", "security alert",
    "update your information", "update your details", "within 24 hours", "enter your otp",
    "card number", "cvv", "your account is limited", "restore access", "re-activate",
    "reactivate your", "immediately", "act now",
)
_OBFUSCATION = re.compile(r"\b(eval|unescape|atob)\s*\(|fromCharCode|document\.write\s*\(", re.I)
_RIGHT_CLICK = re.compile(
    r"(oncontextmenu\s*=\s*[\"']?\s*return\s+false|contextmenu[^;]{0,80}(preventDefault|return\s+false))",
    re.I | re.S,
)


def _c(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x


def _sigmoid(z: float) -> float:
    return 1.0 / (1.0 + math.exp(-z))


@dataclass
class PageResult:
    score: float
    features: dict
    evidence: list[Evidence] = field(default_factory=list)
    version: str = PAGE_VERSION


def _reg(page_url: str, ref: str) -> str | None:
    """Registered domain that `ref` points to, or None for non-http(s) references."""
    try:
        sp = urlsplit(urljoin(page_url, ref))
        if sp.scheme not in ("http", "https") or not sp.hostname:
            return None
        return split_host(sp.hostname.lower())[1]
    except ValueError:
        return None


def _hidden(tag) -> bool:
    style = (tag.get("style") or "").replace(" ", "").lower()
    w = (tag.get("width") or "").strip()
    h = (tag.get("height") or "").strip()
    return "display:none" in style or "visibility:hidden" in style or w in ("0", "1") or h in ("0", "1") or tag.has_attr("hidden")


def analyze_page(html: str, page_url: str) -> PageResult:
    html = (html or "")[:MAX_HTML]
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:  # pragma: no cover
        soup = BeautifulSoup(html, "html.parser")

    page = parse_url(page_url)
    page_reg = page.reg_domain
    title = soup.title.get_text(" ", strip=True) if soup.title else ""

    # ---- resources (collect before scripts are stripped) ----
    refs = []
    for tag, attr in (("script", "src"), ("img", "src"), ("link", "href"), ("iframe", "src")):
        refs += [t.get(attr) for t in soup.find_all(tag, attrs={attr: True})]
    regs = [r for r in (_reg(page.url, x) for x in refs) if r]
    ext_res = sum(1 for r in regs if r != page_reg)
    ext_ratio = ext_res / len(regs) if len(regs) >= 5 else 0.0

    favicon_ext = False
    for link in soup.find_all("link", attrs={"rel": True, "href": True}):
        if "icon" in " ".join(link.get("rel")).lower():
            r = _reg(page.url, link["href"])
            favicon_ext = bool(r and r != page_reg)

    inline_js = " ".join(s.get_text() for s in soup.find_all("script") if not s.get("src"))[:200_000]
    obfuscation_hits = len(_OBFUSCATION.findall(inline_js))
    right_click_blocked = bool(_RIGHT_CLICK.search(html[:300_000]))

    hidden_iframes = sum(1 for f in soup.find_all("iframe") if f.get("src") and _hidden(f))
    meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)}) is not None

    # ---- forms and credential fields ----
    n_password = len(soup.find_all("input", attrs={"type": re.compile(r"^password$", re.I)}))
    form_kinds: list[str] = []  # for forms that ask for secrets
    ext_action_domain = ""
    cred_forms = 0
    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        has_secret = any((i.get("type") or "").lower() == "password" for i in inputs) or any(
            _CRED_NAME.search(f"{i.get('name') or ''} {i.get('id') or ''} {i.get('placeholder') or ''}") for i in inputs
        )
        if not has_secret:
            continue
        cred_forms += 1
        action = (form.get("action") or "").strip()
        low = action.lower()
        if low.startswith("mailto:"):
            form_kinds.append("mailto")
        elif action == "#" or low.startswith("javascript:"):
            form_kinds.append("inert")
        else:
            r = _reg(page.url, action) if action else page_reg
            if r and r != page_reg:
                form_kinds.append("external")
                ext_action_domain = r
            else:
                form_kinds.append("internal")
    collects = n_password > 0 or cred_forms > 0

    # ---- text ----
    anchors = [a.get("href", "").strip() for a in soup.find_all("a", href=True)]
    null_anchors = sum(1 for h in anchors if h in ("#", "") or h.lower().startswith("javascript:"))
    null_ratio = null_anchors / len(anchors) if len(anchors) >= 3 else 0.0

    alts = " ".join((i.get("alt") or "") for i in soup.find_all("img"))
    for t in soup(["script", "style", "noscript"]):
        t.decompose()
    text = soup.get_text(" ", strip=True)[:50_000]
    low_text = (text + " " + alts).lower()
    urgent = sum(1 for p in _URGENT if p in low_text)

    claimed = set(brands_in(title))
    for b in BRANDS:
        if len(re.findall(r"\b" + re.escape(b) + r"\b", low_text)) >= 3:
            claimed.add(b)
    mismatched = sorted(b for b in claimed if page_reg not in BRANDS[b])

    features = {
        "n_password": n_password,
        "n_cred_forms": cred_forms,
        "collects_credentials": collects,
        "ext_form_action": "external" in form_kinds,
        "form_action_domain": ext_action_domain,
        "mailto_form": "mailto" in form_kinds,
        "inert_form": "inert" in form_kinds,
        "brand_mismatch": bool(mismatched),
        "hidden_iframes": hidden_iframes,
        "meta_refresh": meta_refresh,
        "js_obfuscation_hits": obfuscation_hits,
        "right_click_blocked": right_click_blocked,
        "external_resource_ratio": round(ext_ratio, 3),
        "null_anchor_ratio": round(null_ratio, 3),
        "urgent_phrases": urgent,
        "favicon_external": favicon_ext,
        "insecure_password": collects and page.scheme == "http",
    }

    # ---- scoring: transparent weights in log-odds units ----
    logit = BIAS
    ev: list[Evidence] = []

    def add(cond_weight: float, signal: str, detail: str) -> None:
        nonlocal logit
        if cond_weight <= 0:
            return
        logit += cond_weight
        ev.append(Evidence("page", signal, detail, cond_weight))

    if collects:
        add(1.6, "Page asks for a password or other secret", "The page has a form that collects a password, PIN, OTP or card detail.")
    if "external" in form_kinds:
        add(2.4, "Login form sends data to another site", f"The form submits to {ext_action_domain[:60]}, not to {page_reg[:60]}.")
    if "mailto" in form_kinds:
        add(2.0, "Form sends data by email", "The form is wired to an email address instead of a website.")
    if "inert" in form_kinds and "external" not in form_kinds:
        add(0.8, "Form submits through script", "The form has no real destination, so a script decides where the data goes.")
    if mismatched:
        w = 2.8 if collects else 1.0
        add(w, "Page imitates a known brand", f"The page presents itself as {', '.join(mismatched)}, but it is hosted on {page_reg[:60]}.")
    if features["insecure_password"]:
        add(1.0, "Password requested without encryption", "The page collects secrets over plain http.")
    if hidden_iframes:
        add(1.2 * min(hidden_iframes, 2) / 2, "Hidden frame", f"The page loads {hidden_iframes} invisible frame(s) from other addresses.")
    if meta_refresh:
        add(0.6, "Automatic redirect", "The page sends the visitor elsewhere automatically.")
    add(1.1 * _c(obfuscation_hits / 3), "Obfuscated script", "The page's scripts use encoding tricks that hide what they do.")
    if right_click_blocked:
        add(0.7, "Right-click disabled", "The page blocks the context menu, which stops visitors inspecting it.")
    add(0.6 * _c((ext_ratio - 0.5) / 0.5), "Mostly borrowed content", "Most images, scripts and styles are loaded from other domains.")
    add(0.9 * _c((null_ratio - 0.5) / 0.5), "Links that go nowhere", "Most links on the page are empty or do nothing.")
    add(1.2 * _c(urgent / 3), "Pressure language", f"The page uses {urgent} phrases typical of account-security scams.")
    if favicon_ext:
        add(0.5, "Icon from another site", "The page's icon is loaded from a different domain.")

    ev.sort(key=lambda e: e.weight, reverse=True)
    return PageResult(_sigmoid(logit), features, ev)
