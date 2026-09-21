"""Text modality (v0.2): what a message says and who claims to have sent it.

This is a transparent rule-based baseline, the text counterpart of `heuristic-v1`.
It is NOT trained. Before making claims in the paper, train and evaluate an NLP model
on a labelled message corpus and compare it against this baseline.

Limitations worth stating: English-centric phrase lists (with some India-specific scam
wording), no obfuscation handling, no language detection, and sender checks that only
see what the user pastes (no headers, no SPF/DKIM results).
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from email.utils import parseaddr

from .brands import BRANDS, brands_in, is_legit_domain
from .types import Evidence
from .urlfeatures import SUSPICIOUS_TLDS, brand_findings, parse_url

TEXT_VERSION = "text-heuristic-v1"
BIAS = -3.2

_URGENCY = (
    "act now", "immediately", "within 24 hours", "within 48 hours", "urgent", "urgently",
    "final notice", "last warning", "expires today", "expire today", "limited time",
    "right away", "as soon as possible", "today only",
)
_CREDENTIAL = re.compile(
    r"\b(verify|confirm|update|validate|re-?enter|share|send|provide)\s+(your\s+)?"
    r"(account|identity|password|otp|pin|upi pin|card|details|kyc|banking|bank details|information)\b",
    re.I,
)
_THREAT_RE = re.compile(
    r"\b(account|card|number|sim|access|service|electricity|wallet)\b.{0,30}\b"
    r"(has been|have been|will be|is being|is)\s+"
    r"(suspended|blocked|locked|closed|limited|disconnected|deactivated|terminated|restricted)\b",
    re.I | re.S,
)
_THREAT_PHRASES = (
    "legal action", "unauthorized transaction", "unauthorised transaction", "unauthorized login",
    "unusual activity", "unusual sign-in", "suspicious activity", "security alert", "arrest warrant",
)
_FINANCIAL = (
    "bank account", "card number", "cvv", "upi pin", "refund", "you have won", "you've won",
    "lottery", "prize", "gift card", "wire transfer", "bitcoin", "crypto", "payment failed",
    "payment declined", "kyc", "pan card", "aadhaar", "tax refund", "cashback",
)
_CLICK = re.compile(r"\b(click|tap|press)\s+(here|the link|below|on the link|this link)\b", re.I)
FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me", "protonmail.com",
             "rediffmail.com", "aol.com", "icloud.com"}

_URL = re.compile(
    r"(?i)\b(?:https?://|www\.)[^\s<>\"'\)\]]+"
    r"|\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd|shorturl\.at)/[^\s<>\"'\)\]]+"
)


def _c(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x


def extract_urls(text: str, limit: int = 3) -> tuple[list[str], int]:
    """Return (first `limit` distinct URLs, total distinct URLs found)."""
    seen: dict[str, str] = {}
    for m in _URL.finditer(text):
        u = m.group(0).rstrip(".,;:!?)")
        seen.setdefault(u.lower(), u)
    urls = list(seen.values())
    return urls[:limit], len(urls)


@dataclass
class TextResult:
    score: float
    features: dict
    evidence: list[Evidence] = field(default_factory=list)
    claimed_brands: list[str] = field(default_factory=list)
    sender_domain: str = ""
    version: str = TEXT_VERSION


def analyze_text(text: str, sender: str = "", subject: str = "") -> TextResult:
    body = f"{subject}\n{text}"
    low = body.lower()
    name, addr = parseaddr(sender or "")
    sender_domain = addr.rsplit("@", 1)[-1].lower().strip() if "@" in addr else ""

    n_urgent = sum(1 for p in _URGENCY if p in low)
    n_cred = len(_CREDENTIAL.findall(body))
    n_threat = len(_THREAT_RE.findall(body)) + sum(1 for p in _THREAT_PHRASES if p in low)
    n_fin = sum(1 for p in _FINANCIAL if p in low)
    n_click = len(_CLICK.findall(body))
    letters = [ch for ch in body if ch.isalpha()]
    caps_ratio = (sum(ch.isupper() for ch in letters) / len(letters)) if len(letters) >= 30 else 0.0
    shouting = caps_ratio > 0.5 or "!!!" in body

    # brands the message speaks for: from its prose, not from the URLs inside it (a link on
    # github.io is not a claim to be GitHub)
    claimed = sorted(brands_in(f"{subject} {name} {_URL.sub(' ', text)}"))

    features = {
        "urgency_phrases": n_urgent, "credential_requests": n_cred, "threat_phrases": n_threat,
        "financial_terms": n_fin, "click_prompts": n_click, "shouting": shouting,
        "sender_present": bool(sender_domain), "claimed_brands": len(claimed),
    }

    logit = BIAS
    ev: list[Evidence] = []

    def add(w: float, signal: str, detail: str) -> None:
        nonlocal logit
        if w <= 0:
            return
        logit += w
        ev.append(Evidence("text", signal, detail, w))

    add(1.8 * _c(n_cred / 1.5), "Asks you to verify or hand over details",
        "The message asks you to verify, confirm or send account details, a password, PIN, OTP or KYC.")
    add(1.6 * _c(n_threat / 1.5), "Threatens to cut you off",
        "The message says an account or service is suspended or about to be, or warns of legal trouble.")
    add(1.2 * _c(n_urgent / 2), "Pressure to act fast", f"The message uses {n_urgent} urgency phrase(s) to rush you.")
    add(1.0 * _c(n_fin / 2), "Money or identity bait", "The message talks about refunds, prizes, card or KYC details.")
    add(0.6 if n_click else 0.0, "Pushes you to click", "The message tells you to click or tap a link.")
    add(0.5 if shouting else 0.0, "Shouting", "The message is mostly capitals or full of exclamation marks.")

    # sender checks: only what the user pasted
    if sender_domain:
        sender_brands = brands_in(name)
        bad = [b for b in sender_brands if not is_legit_domain(b, _reg(sender_domain))]
        if bad:
            add(2.6, "Sender name doesn't match sender address",
                f"The sender name says {', '.join(bad)}, but the address is @{sender_domain[:60]}.")
        elif sender_domain in FREE_MAIL and claimed:
            add(1.2, "Big brand from a free mail account",
                f"The message speaks for {', '.join(claimed)} but was sent from @{sender_domain}.")
        try:
            sp = parse_url("https://" + sender_domain)
            found = brand_findings(sp)
            if found["domain"] or found["subdomain"]:
                add(2.4, "Look-alike sender domain",
                    f"The sender domain {sender_domain[:60]} imitates {', '.join(found['domain'] + found['subdomain'])}.")
            elif sp.suffix.split(".")[-1] in SUSPICIOUS_TLDS:
                add(1.0, "Sender domain ending often abused", f"The sender domain {sender_domain[:60]} uses a throwaway-style ending.")
        except ValueError:
            pass

    ev.sort(key=lambda e: e.weight, reverse=True)
    return TextResult(1.0 / (1.0 + math.exp(-logit)), features, ev, claimed, sender_domain)


def _reg(domain: str) -> str:
    from .urlfeatures import split_host

    return split_host(domain)[1]


__all__ = ["analyze_text", "extract_urls", "TextResult", "TEXT_VERSION", "BRANDS"]
