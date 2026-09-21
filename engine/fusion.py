"""Late fusion of per-modality phishing probabilities.

    z = bias + sum over available modalities of weight[m] * (logit(p[m]) - prior[m])

A modality that is missing (page could not be opened, no text supplied) simply
contributes nothing: "no evidence" is neutral, not "safe".

The v0.1 detectors are logistic scores with a built-in negative prior (about -3), so a
modality that saw nothing suspicious still reports a strongly negative logit. Subtracting
that prior turns each score into "evidence found" (0 when nothing was found), which stops
several quiet modalities from drowning out one loud one. The default weights and priors are
hand-set (`logit-avg-v2`). `LogitFusion.fit` instead learns weights and an intercept on raw
logits (priors = 0) with logistic regression on a validation slice, which also makes the
output a Platt-style calibrated probability *for that slice's class balance*. State that
caveat if you show the number to users as a probability.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_WEIGHTS = {"url": 0.4, "page": 0.6, "text": 0.8}
DEFAULT_PRIORS = {"url": -3.2, "page": -3.0, "text": -3.2}  # the BIAS constants of the heuristic detectors
DEFAULT_BIAS = -3.0
_EPS = 1e-4


def logit(p: float) -> float:
    p = min(max(p, _EPS), 1 - _EPS)
    return math.log(p / (1 - p))


def sigmoid(z: float) -> float:
    return 1.0 / (1.0 + math.exp(-z))


@dataclass
class LogitFusion:
    weights: dict = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    bias: float = DEFAULT_BIAS
    version: str = "logit-avg-v2"
    calibrated: bool = False
    meta: dict = field(default_factory=dict)
    priors: dict = field(default_factory=lambda: dict(DEFAULT_PRIORS))

    def predict(self, scores: dict) -> float:
        """`scores` maps modality name -> probability, or None when unavailable."""
        z = self.bias
        for name, p in scores.items():
            if p is not None:
                z += self.weights.get(name, 0.0) * (logit(p) - self.priors.get(name, 0.0))
        return sigmoid(z)

    @classmethod
    def fit(cls, rows: list[dict], y, version: str = "logit-fit-v1", C: float = 1.0, meta: dict | None = None):
        """Fit on validation rows: each row maps modality -> probability (None allowed)."""
        from sklearn.linear_model import LogisticRegression

        names = sorted({k for r in rows for k in r})
        X = [[logit(r[n]) if r.get(n) is not None else 0.0 for n in names] for r in rows]
        clf = LogisticRegression(C=C, max_iter=1000).fit(X, list(y))
        weights = {n: float(w) for n, w in zip(names, clf.coef_[0])}
        return cls(weights, float(clf.intercept_[0]), version, calibrated=True, meta=meta or {}, priors={})

    def save(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps({
            "version": self.version, "weights": self.weights, "bias": self.bias,
            "priors": self.priors, "calibrated": self.calibrated, "meta": self.meta}, indent=2))

    @classmethod
    def load(cls, path: str | Path) -> "LogitFusion":
        d = json.loads(Path(path).read_text())
        return cls(d["weights"], d["bias"], d["version"], d.get("calibrated", False), d.get("meta", {}),
                   d.get("priors", {}))


def fuse(p_url: float, p_page: float, w_url: float = 0.4, w_page: float = 0.6) -> float:
    """Two-modality helper with the default priors, kept for the experiments and tests."""
    return LogitFusion({"url": w_url, "page": w_page}).predict({"url": p_url, "page": p_page})
