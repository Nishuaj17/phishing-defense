"""Shared result types.

The result keeps four things apart on purpose:

    probability          model output (0-1); `calibrated` says whether it was fitted to be one
    risk                 probability rescaled to 0-100 for display
    label / verified     what we conclude, and whether we could actually check it
    recommended_action   allow / warn / block: advice. `enforcement` says who enforces it
                         (always "advisory" in the web app; a browser extension or mail
                         gateway would be the enforcing layer)
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Evidence:
    """One human-readable reason behind a score.

    weight > 0 raises risk. Units are roughly log-odds so evidence from different
    stages can be ranked together.
    """

    stage: str  # "url" | "page" | "text" | "intel"
    signal: str
    detail: str
    weight: float


@dataclass
class StageResult:
    name: str  # "url" | "page" | "text"
    title: str
    score: float | None  # probability of phishing, None if the stage did not run
    ms: float
    outcome: str  # "stop" | "escalate" | "skipped" | "unavailable" | "done"
    note: str = ""


@dataclass
class Analysis:
    id: str
    kind: str  # "link" | "message"
    url: str | None
    final_url: str | None
    risk: int  # 0-100
    probability: float
    calibrated: bool
    label: str  # safe | suspicious | phishing | unverified
    verified: bool  # False when the page was needed but could not be opened
    recommended_action: str  # allow | warn | block
    enforcement: str  # "advisory"
    mode: str  # cascade | full
    stopped_at: str  # url | page | intel | text: which modality produced the decision
    stages: list
    modalities: dict  # per-modality status and score, including ones not built yet
    evidence: list  # list[dict] with a normalised "impact" 0-1
    links: list = field(default_factory=list)  # per-link summary for messages
    parts: dict = field(default_factory=dict)  # url anatomy for display
    guidance: dict = field(default_factory=dict)
    indicators: list = field(default_factory=list)  # indicators of compromise
    thresholds: dict = field(default_factory=dict)
    versions: dict = field(default_factory=dict)
    latency_ms: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)
