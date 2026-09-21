"""The cascade: cheap address check first, page inspection only when needed.

Why a cascade: the address check costs microseconds and never touches the (possibly
malicious) server; opening the page costs hundreds of milliseconds and exposes the analyser.
The thresholds t_low / t_high control the latency-versus-accuracy trade-off and are the main
experimental knob (see experiments/).

`analyze_message` (v0.2) reads a pasted email/SMS, runs each link through the same cascade,
and fuses the text, address and page evidence.
"""
from __future__ import annotations

import re
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from .brands import is_legit_domain
from .fetcher import FetchResult, fetch_page
from .fusion import LogitFusion, fuse, logit, sigmoid  # noqa: F401  (fuse re-exported for callers)
from .pagefeatures import PAGE_VERSION, analyze_page
from .response import guidance, indicators
from .textfeatures import TEXT_VERSION, analyze_text, extract_urls
from .threatintel import ThreatIntel
from .types import Analysis, Evidence, StageResult
from .urlfeatures import ParsedURL, parse_url
from .urlmodel import UrlModel

SUSPICIOUS_AT = 30  # risk >= 30 -> warn
PHISHING_AT = 65    # risk >= 65 -> block
MAX_URL_LEN = 2048
MAX_TEXT_LEN = 5000
NOT_BUILT = {"status": "not_implemented"}


def stage1_decision(p_url: float, t_low: float, t_high: float) -> str:
    if p_url <= t_low:
        return "safe"
    if p_url >= t_high:
        return "phishing"
    return "escalate"


def label_action(risk: int) -> tuple[str, str]:
    if risk >= PHISHING_AT:
        return "phishing", "block"
    if risk >= SUSPICIOUS_AT:
        return "suspicious", "warn"
    return "safe", "allow"


def normalise_input(raw: str) -> ParsedURL:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Enter a link to check.")
    if len(raw) > MAX_URL_LEN:
        raise ValueError(f"Links longer than {MAX_URL_LEN} characters are not accepted.")
    if re.search(r"\s", raw) or any(ord(c) < 32 for c in raw):
        raise ValueError("A link cannot contain spaces or control characters.")
    return parse_url(raw)  # raises ValueError for malformed input


def _top_evidence(evidence: list[Evidence], n: int = 8) -> list[dict]:
    top = sorted(evidence, key=lambda e: e.weight, reverse=True)[:n]
    peak = max((e.weight for e in top), default=1.0) or 1.0
    return [{"stage": e.stage, "signal": e.signal, "detail": e.detail, "impact": round(e.weight / peak, 3)} for e in top]


class Analyzer:
    def __init__(
        self,
        url_model: UrlModel | None = None,
        fetch: Callable[[str], FetchResult] = fetch_page,
        t_low: float = 0.06,
        t_high: float = 0.93,
        fusion: LogitFusion | None = None,
        ti: ThreatIntel | None = None,
        ti_floor: float = 0.95,
        max_links: int = 3,
    ):
        self.url_model = url_model or UrlModel()
        self.fetch = fetch
        self.t_low, self.t_high = t_low, t_high
        self.fusion = fusion or LogitFusion()
        fitted_for = self.fusion.meta.get("url_model")
        if fitted_for and fitted_for != self.url_model.version:
            # A fusion fitted on one URL model's scores is wrong for another model's scores.
            raise ValueError(f"Fusion was fitted for URL model '{fitted_for}' but '{self.url_model.version}' is loaded. "
                             "Refit it with experiments.fit_fusion.")
        self.ti = ti
        self.ti_floor = ti_floor
        self.max_links = max_links

    # ------------------------------------------------------------------ links
    def analyze(self, raw_url: str, mode: str = "cascade", html: str | None = None,
                final_url: str | None = None) -> Analysis:
        """Analyse a link. Pass `html` to skip fetching (used by offline experiments)."""
        return self._analyze_link(raw_url, mode, html, final_url)[0]

    def _analyze_link(self, raw_url: str, mode: str, html: str | None = None,
                      final_url: str | None = None) -> tuple[Analysis, list[Evidence]]:
        t_start = time.perf_counter()
        p = normalise_input(raw_url)
        stages: list[StageResult] = []
        hits = self.ti.check(p) if self.ti else []

        # ---- Stage 1: the address ----
        t0 = time.perf_counter()
        pred = self.url_model.predict(p.url)
        ms1 = (time.perf_counter() - t0) * 1000
        s1 = pred.score
        decision = "phishing" if hits else stage1_decision(s1, self.t_low, self.t_high)
        run_page = (mode == "full" and not hits) or decision == "escalate"

        if hits:
            note = "Listed on a threat list, so the page was not opened."
            outcome = "stop"
        elif decision == "escalate":
            note, outcome = "Not clear from the address alone, so the page was opened.", "escalate"
        elif run_page:
            note, outcome = "Page inspection was requested as well.", "escalate"
        elif decision == "safe":
            note, outcome = "Nothing in the address called for a closer look.", "stop"
        else:
            note, outcome = "The address alone is decisive, so the page was not opened.", "stop"
        stages.append(StageResult("url", "Address check", s1, ms1, outcome, note))

        evidence: list[Evidence] = list(pred.evidence)
        final_p = s1
        stopped_at = "url"
        opened_url: str | None = None
        page_failed = False
        page_features: dict = {}
        modalities = {
            "url": {"status": "done", "score": round(s1, 4)},
            "webpage": {"status": "skipped"},
            "text": {"status": "not_applicable"},
            "visual": dict(NOT_BUILT),
            "threat_intel": {
                "status": "hit" if hits else ("clear" if self.ti and self.ti.configured else "not_configured"),
                "sources": sorted({h.source for h in hits}),
            },
        }

        # ---- Stage 2: the page ----
        if run_page:
            t1 = time.perf_counter()
            if html is None:
                fr = self.fetch(p.url)
                fetched_ms, page_html, opened_url, err = fr.ms, fr.html, fr.final_url, ("" if fr.ok else fr.error)
            else:
                fetched_ms, page_html, opened_url, err = 0.0, html, final_url or p.url, ""
            if err:
                page_failed = True
                ms = (time.perf_counter() - t1) * 1000
                stages.append(StageResult("page", "Page check", None, ms, "unavailable",
                                          f"{err} The verdict uses the address alone."))
                modalities["webpage"] = {"status": "unavailable", "reason": err}
            else:
                res = analyze_page(page_html, opened_url or p.url)
                ms2 = (time.perf_counter() - t1) * 1000 + fetched_ms
                stages.append(StageResult("page", "Page check", res.score, ms2, "done",
                                          "Read the page's forms, scripts and resources."))
                modalities["webpage"] = {"status": "done", "score": round(res.score, 4)}
                evidence += res.evidence
                page_features = res.features
                final_p = self.fusion.predict({"url": s1, "page": res.score})
                stopped_at = "page"
        else:
            stages.append(StageResult("page", "Page check", None, 0.0, "skipped", "Not needed."))

        # ---- policy: a threat-list hit is a floor, never a model input ----
        if hits:
            final_p = max(final_p, self.ti_floor)
            stopped_at = "intel"
            for h in hits:
                evidence.append(Evidence("intel", "Listed on a threat list",
                                         f"{h.indicator[:80]} appears on {h.source}.", 3.5))

        verified = not (decision == "escalate" and page_failed)
        risk = round(final_p * 100)
        label, action = label_action(risk)
        if not verified and label == "safe":
            label, action = "unverified", "warn"

        analysis = Analysis(
            id=secrets.token_hex(6),
            kind="link",
            url=p.url,
            final_url=opened_url,
            risk=risk,
            probability=round(final_p, 4),
            calibrated=bool(self.fusion.calibrated and stopped_at == "page"),
            label=label,
            verified=verified,
            recommended_action=action,
            enforcement="advisory",
            mode=mode,
            stopped_at=stopped_at,
            stages=[s.__dict__ for s in stages],
            modalities=modalities,
            evidence=_top_evidence(evidence),
            parts={
                "scheme": p.scheme,
                "subdomain": "" if p.subdomain in ("", "www") else p.subdomain,
                "domain": p.reg_domain,
                "rest": (p.path or "") + (("?" + p.query) if p.query else ""),
                "port": p.port,
            },
            guidance=guidance(label, action),
            indicators=indicators(p.url, p.reg_domain, page_features.get("form_action_domain", "")),
            thresholds={"low": self.t_low, "high": self.t_high},
            versions=self._versions(),
            latency_ms=round((time.perf_counter() - t_start) * 1000, 1),
        )
        return analysis, evidence

    # --------------------------------------------------------------- messages
    def analyze_message(self, text: str, sender: str = "", subject: str = "", mode: str = "cascade") -> Analysis:
        """Analyse a pasted email/SMS: its wording, its sender, and every link in it."""
        t_start = time.perf_counter()
        text = (text or "").strip()
        if not text:
            raise ValueError("Paste the message text first.")
        if len(text) > MAX_TEXT_LEN:
            raise ValueError(f"Messages longer than {MAX_TEXT_LEN} characters are not accepted.")
        if len(sender) > 320 or len(subject) > 300:
            raise ValueError("The sender or subject is too long.")

        t0 = time.perf_counter()
        tres = analyze_text(text, sender, subject)
        ms_text = (time.perf_counter() - t0) * 1000
        urls, total_links = extract_urls(text, self.max_links)

        def one(u: str):
            try:
                return self._analyze_link(u, mode)
            except ValueError:
                return None  # a malformed link in the text is not an input error

        with ThreadPoolExecutor(max_workers=max(1, len(urls))) as pool:
            results = [r for r in pool.map(one, urls) if r is not None]
        worst, worst_ev = max(results, key=lambda r: r[0].risk) if results else (None, [])

        evidence: list[Evidence] = list(tres.evidence)
        p_text = tres.score
        f = tres.features
        pressure = f["credential_requests"] + f["threat_phrases"] + f["urgency_phrases"] + f["click_prompts"]

        # text-versus-link consistency: the message speaks for a brand its links don't belong to
        if results and tres.claimed_brands and pressure > 0:
            domains = {r[0].parts["domain"] for r in results}
            mismatched = [b for b in tres.claimed_brands if not any(is_legit_domain(b, d) for d in domains)]
            if mismatched:
                p_text = sigmoid(logit(p_text) + 2.2)
                evidence.append(Evidence(
                    "text", "Message and links disagree",
                    f"The message talks about {', '.join(mismatched)}, but its links go to {', '.join(sorted(domains)[:3])}.",
                    2.2))

        scores = {"text": p_text}
        if worst is not None:
            scores["url"] = worst.modalities["url"].get("score")
            scores["page"] = worst.modalities["webpage"].get("score")
        fused = self.fusion.predict(scores)
        # A malicious link is malicious whatever the surrounding words say, so the worst
        # link's own probability is a floor. Otherwise an innocent-looking sentence could
        # dilute a phishing URL.
        final_p = max(fused, worst.probability if worst else 0.0)

        if worst is not None:
            evidence += worst_ev
        verified = all(r[0].verified for r in results) if results else True
        risk = round(final_p * 100)
        label, action = label_action(risk)
        if not verified and label == "safe":
            label, action = "unverified", "warn"

        if worst is not None and worst.stopped_at == "intel":
            stopped_at = "intel"
        elif worst is not None and worst.risk >= risk - 1:
            stopped_at = worst.stopped_at
        else:
            stopped_at = "text"

        stages = [StageResult("text", "Message check", p_text, ms_text, "done",
                              "Read the wording and the sender.").__dict__]
        if worst is not None:
            stages += worst.stages
        note = f"{total_links - len(urls)} more link(s) in the message were not checked." if total_links > len(urls) else ""
        if note and stages:
            stages[0]["note"] += " " + note

        modalities = {
            "text": {"status": "done", "score": round(p_text, 4)},
            "url": worst.modalities["url"] if worst else {"status": "not_applicable"},
            "webpage": worst.modalities["webpage"] if worst else {"status": "not_applicable"},
            "visual": dict(NOT_BUILT),
            "threat_intel": worst.modalities["threat_intel"] if worst else {"status": "not_applicable"},
        }
        links = [{"url": a.url, "domain": a.parts["domain"], "risk": a.risk, "label": a.label,
                  "recommended_action": a.recommended_action} for a, _ in results]
        iocs = indicators(None, sender_domain=tres.sender_domain)
        for a, _ in results:
            iocs += [i for i in a.indicators if i not in iocs]

        analysis = Analysis(
            id=secrets.token_hex(6),
            kind="message",
            url=None,
            final_url=worst.final_url if worst else None,
            risk=risk,
            probability=round(final_p, 4),
            calibrated=False,
            label=label,
            verified=verified,
            recommended_action=action,
            enforcement="advisory",
            mode=mode,
            stopped_at=stopped_at,
            stages=stages,
            modalities=modalities,
            evidence=_top_evidence(evidence),
            links=links,
            parts=worst.parts if worst else {},
            guidance=guidance(label, action),
            indicators=iocs,
            thresholds={"low": self.t_low, "high": self.t_high},
            versions={**self._versions(), "text_model": TEXT_VERSION},
            latency_ms=round((time.perf_counter() - t_start) * 1000, 1),
        )
        return analysis

    def _versions(self) -> dict:
        return {"url_model": self.url_model.version, "page_model": PAGE_VERSION, "fusion": self.fusion.version}
