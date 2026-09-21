"""Brand names commonly impersonated, mapped to their legitimate registered domains.

This is a small hand-written seed list. For the paper, replace or extend it with
a proper brand corpus (e.g. the Tranco top sites plus a curated list of targeted
brands from PhishTank/OpenPhish statistics) and report which list you used.
"""
from __future__ import annotations

import re

BRANDS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypal.me"),
    "google": ("google.com", "google.co.in", "gmail.com", "youtube.com", "gstatic.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazon.in", "amazon.co.uk"),
    "facebook": ("facebook.com", "fb.com", "meta.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com",),
    "netflix": ("netflix.com",),
    "linkedin": ("linkedin.com",),
    "dropbox": ("dropbox.com",),
    "github": ("github.com",),
    "dhl": ("dhl.com",),
    "fedex": ("fedex.com",),
    "sbi": ("sbi.co.in", "onlinesbi.sbi", "sbicard.com"),
    "hdfc": ("hdfcbank.com",),
    "icici": ("icicibank.com",),
    "axisbank": ("axisbank.com",),
    "paytm": ("paytm.com",),
    "phonepe": ("phonepe.com",),
    "irctc": ("irctc.co.in",),
    "uidai": ("uidai.gov.in",),
}

_TOKEN = re.compile(r"[^a-z0-9$]+")
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "$": "s"})

# Words attackers glue onto a brand ("paypal-secure", "my-amazon"). Requiring one of
# these avoids flagging "pineapple" as Apple.
_AFFIXES = frozenset(
    {
        "secure", "login", "signin", "verify", "account", "support", "help", "service",
        "services", "online", "pay", "payment", "payments", "bank", "banking", "update",
        "id", "auth", "web", "mail", "care", "team", "my", "mobile", "app", "official",
        "wallet", "customer", "alert", "security", "portal", "confirm", "billing",
        "refund", "kyc", "india",
    }
)


def brands_in(text: str) -> set[str]:
    """Brands referenced in `text`, tolerating simple leet-speak (paypa1, amaz0n)."""
    found: set[str] = set()
    for tok in _TOKEN.split(text.lower()):
        if not tok:
            continue
        for cand in {tok, tok.translate(_LEET)}:
            for brand in BRANDS:
                if cand == brand:
                    found.add(brand)
                elif cand.startswith(brand) and cand[len(brand):] in _AFFIXES:
                    found.add(brand)
                elif cand.endswith(brand) and cand[: -len(brand)] in _AFFIXES:
                    found.add(brand)
    return found


def is_legit_domain(brand: str, registered_domain: str) -> bool:
    return registered_domain in BRANDS.get(brand, ())
