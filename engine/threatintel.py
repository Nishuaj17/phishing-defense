"""Threat intelligence (v0.4 seam).

Design rules, because they decide whether your evaluation is honest:

1. Threat intel is a POLICY layer, not an ML feature. A hit sets a risk floor and skips
   opening the page; it is never fed into the URL/page models or the fusion weights.
2. `experiments/evaluate.py` never touches this module. If your labels come from a feed
   (PhishTank, OpenPhish, URLhaus...), using the same feed at inference would be circular.
   To measure what intel adds, evaluate only on URLs first seen AFTER the list snapshot.
3. Providers must be fast and fail closed-to-neutral: an error or timeout is "no hit".

Ships with one provider, `LocalBlocklist` (a text file of domains/URLs you control), which
works offline and is testable. A real API provider (Google Safe Browsing, URLhaus, ...) only
needs a `.lookup(ParsedURL) -> TIHit | None` method plus its own caching and timeout; add it
to the `ThreatIntel` list. None is included because they need keys, network and terms review.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .urlfeatures import ParsedURL


@dataclass(frozen=True)
class TIHit:
    source: str
    indicator: str
    kind: str  # "domain" | "url"


class LocalBlocklist:
    """One entry per line: a domain (`evil.example`) or a full URL. `#` starts a comment."""

    def __init__(self, path: str | Path, name: str | None = None):
        self.name = name or Path(path).name
        self.domains: set[str] = set()
        self.urls: set[str] = set()
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            s = line.strip().lower()
            if not s or s.startswith("#"):
                continue
            if "/" in s:
                self.urls.add(s.split("://", 1)[-1].rstrip("/"))
            else:
                self.domains.add(s.lstrip("."))

    def lookup(self, p: ParsedURL) -> TIHit | None:
        key = p.url.lower().split("://", 1)[-1].rstrip("/")
        if key in self.urls:
            return TIHit(self.name, p.url, "url")
        labels = p.host.split(".")
        for i in range(len(labels) - 1):  # the host and each parent domain
            parent = ".".join(labels[i:])
            if parent in self.domains:
                return TIHit(self.name, parent, "domain")
        return None


class ThreatIntel:
    def __init__(self, providers=()):
        self.providers = list(providers)

    @property
    def configured(self) -> bool:
        return bool(self.providers)

    def check(self, p: ParsedURL) -> list[TIHit]:
        hits: list[TIHit] = []
        for prov in self.providers:
            try:
                hit = prov.lookup(p)
            except Exception:  # a broken provider must never break analysis
                continue
            if hit:
                hits.append(hit)
        return hits
