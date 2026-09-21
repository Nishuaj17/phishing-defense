"""Stage 1 scorer.

Two interchangeable back ends:

* ``heuristic-v1``: hand-weighted logistic score over the URL features. It is a
  transparent *prior* and doubles as a baseline your trained model must beat.
* a trained scikit-learn bundle produced by ``ml/train_url_model.py``.

Only load model files you trained yourself: joblib files are pickles.
"""
from __future__ import annotations

import math
import os
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from .types import Evidence
from .urlfeatures import FEATURE_NAMES, brand_findings, extract_features, parse_url

HEURISTIC_VERSION = "heuristic-v1"
BIAS = -3.2


def _c(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x


# feature -> (weight, transform of the feature dict into 0..1)
HEURISTIC = {
    "has_ip_host": (2.6, lambda f: f["has_ip_host"]),
    "has_at": (1.8, lambda f: f["has_at"]),
    "url_len": (1.0, lambda f: _c((f["url_len"] - 75) / 75)),
    "n_subdomains": (1.0, lambda f: _c((f["n_subdomains"] - 2) / 3)),
    "n_hyphens_host": (1.4, lambda f: _c((f["n_hyphens_host"] - 1) / 3)),
    "digit_ratio_host": (1.2, lambda f: _c(f["digit_ratio_host"] / 0.4)),
    "host_entropy": (0.6, lambda f: _c((f["host_entropy"] - 3.4) / 1.0)),
    "is_https": (0.9, lambda f: 1.0 - f["is_https"]),
    "has_punycode": (1.5, lambda f: f["has_punycode"]),
    "suspicious_tld": (1.3, lambda f: f["suspicious_tld"]),
    "is_shortener": (0.8, lambda f: f["is_shortener"]),
    "is_free_hosting": (0.7, lambda f: f["is_free_hosting"]),
    "n_sensitive_words": (1.3, lambda f: _c(f["n_sensitive_words"] / 3)),
    "brand_in_domain_mismatch": (3.0, lambda f: f["brand_in_domain_mismatch"]),
    "brand_in_subdomain_mismatch": (2.6, lambda f: f["brand_in_subdomain_mismatch"]),
    "brand_in_path_mismatch": (1.6, lambda f: f["brand_in_path_mismatch"]),
    "n_percent_encoded": (0.8, lambda f: _c(f["n_percent_encoded"] / 6)),
    "has_double_slash_path": (0.8, lambda f: f["has_double_slash_path"]),
    "has_port_nonstd": (1.0, lambda f: f["has_port_nonstd"]),
}

# name -> (title, detail template). {v} is the raw feature value.
EXPLAIN = {
    "has_ip_host": ("Address is a raw IP number", "The link points to a numeric address instead of a named site."),
    "has_at": ("Text before an @ sign", "Everything before the @ is ignored by the browser; attackers use it to disguise the real site."),
    "url_len": ("Very long address", "The link is {v:.0f} characters long, which hides where it really goes."),
    "n_subdomains": ("Many subdomains", "The address stacks {v:.0f} subdomains in front of the real domain."),
    "n_hyphens_host": ("Hyphens in the domain", "The domain contains {v:.0f} hyphens, common in made-up lookalike names."),
    "digit_ratio_host": ("Digits in the domain", "Many of the domain's characters are digits."),
    "host_entropy": ("Random-looking domain", "The domain name looks machine-generated."),
    "is_https": ("Not encrypted", "The link uses plain http, so anything typed on the page is sent unprotected."),
    "has_punycode": ("Lookalike characters", "The domain uses encoded international characters that can imitate other letters."),
    "suspicious_tld": ("Domain ending often abused", "The domain ends in an extension that is frequently used for throwaway sites."),
    "is_shortener": ("Shortened link", "A link shortener hides the real destination."),
    "is_free_hosting": ("Free hosting platform", "The page is hosted on a free platform anyone can sign up for."),
    "n_sensitive_words": ("Account words in the address", "The address contains {v:.0f} word(s) such as login, verify or account."),
    "n_percent_encoded": ("Encoded characters", "The address contains {v:.0f} percent-encoded characters."),
    "has_double_slash_path": ("Odd path", "The path contains a double slash, a common redirect trick."),
    "has_port_nonstd": ("Unusual port", "The link uses a non-standard network port."),
}


def _sigmoid(z: float) -> float:
    return 1.0 / (1.0 + math.exp(-z))


@dataclass
class UrlPrediction:
    score: float
    evidence: list[Evidence]
    version: str


class UrlModel:
    def __init__(self, path: str | os.PathLike | None = None):
        self._bundle = None
        if path and Path(path).exists():
            import joblib

            self._bundle = joblib.load(path)

    @property
    def kind(self) -> str:
        return "ml" if self._bundle else "heuristic"

    @property
    def version(self) -> str:
        return self._bundle["version"] if self._bundle else HEURISTIC_VERSION

    @property
    def split_ts(self) -> float | None:
        """Timestamp from which data was held out during training (None for the heuristic)."""
        return self._bundle.get("split_ts") if self._bundle else None

    def predict(self, url: str) -> UrlPrediction:
        feats = extract_features(url)
        brand_text = self._brand_evidence(url, feats)
        if self._bundle is None:
            return self._predict_heuristic(feats, brand_text)
        return self._predict_ml(feats, brand_text)

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _brand_evidence(url: str, feats: dict) -> list[Evidence]:
        p = parse_url(url)
        found = brand_findings(p)
        out: list[Evidence] = []
        names = {
            "domain": ("brand_in_domain_mismatch", "Brand name inside a different domain"),
            "subdomain": ("brand_in_subdomain_mismatch", "Brand name used as a subdomain"),
            "path": ("brand_in_path_mismatch", "Brand name in the link path"),
        }
        for key, (feat, title) in names.items():
            if found[key]:
                brands = ", ".join(found[key])
                detail = f"The link mentions {brands}, but the site is {p.reg_domain}, which does not belong to them."
                weight = HEURISTIC[feat][0]
                out.append(Evidence("url", title, detail, weight))
        return out

    def _predict_heuristic(self, feats: dict, brand_ev: list[Evidence]) -> UrlPrediction:
        logit = BIAS
        evidence: list[Evidence] = list(brand_ev)
        for name, (weight, transform) in HEURISTIC.items():
            contrib = weight * transform(feats)
            logit += contrib
            if name in EXPLAIN and contrib >= 0.15:
                title, tmpl = EXPLAIN[name]
                evidence.append(Evidence("url", title, tmpl.format(v=feats.get(name, 0.0)), contrib))
        evidence.sort(key=lambda e: e.weight, reverse=True)
        return UrlPrediction(_sigmoid(logit), evidence, HEURISTIC_VERSION)

    def _predict_ml(self, feats: dict, brand_ev: list[Evidence]) -> UrlPrediction:
        b = self._bundle
        names = b["feature_names"]
        model = b["model"]
        x = np.array([[feats[n] for n in names]], dtype=float)
        # Occlusion explanation: how much does risk drop if a feature is set to its
        # benign median? Model-agnostic and needs no extra dependency. Swap for SHAP
        # in the paper if you want Shapley-value guarantees.
        X = np.repeat(x, len(names), axis=0)
        for i in range(len(names)):
            X[i, i] = b["medians"][i]
        probs = model.predict_proba(np.vstack([x, X]))[:, 1]
        base, occluded = float(probs[0]), probs[1:]
        evidence: list[Evidence] = list(brand_ev)
        shown = {e.signal for e in evidence}
        for i in np.argsort(base - occluded)[::-1][:6]:
            delta = float(base - occluded[i])
            name = names[i]
            if delta < 0.02 or name.startswith("brand_in_"):
                continue
            title, tmpl = EXPLAIN.get(name, (name.replace("_", " ").capitalize(), "This feature pushed the score up."))
            if title in shown:
                continue
            # x4 puts probability deltas roughly on the log-odds scale of the heuristics
            evidence.append(Evidence("url", title, tmpl.format(v=feats.get(name, 0.0)), delta * 4))
        evidence.sort(key=lambda e: e.weight, reverse=True)
        return UrlPrediction(base, evidence, self.version)


__all__ = ["UrlModel", "UrlPrediction", "FEATURE_NAMES"]
