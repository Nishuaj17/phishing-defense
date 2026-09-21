"""Calibration diagnostics: does a predicted 0.9 mean phishing about 90% of the time?

Report Brier score and expected calibration error (ECE) next to AUC. A model can rank well
and still be badly calibrated, and the UI must not present a score as a probability unless
these numbers support it.
"""
from __future__ import annotations

import numpy as np


def reliability_bins(y, p, bins: int = 10) -> list[dict]:
    y, p = np.asarray(y, dtype=float), np.asarray(p, dtype=float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    out = []
    for b in range(bins):
        m = idx == b
        if m.any():
            out.append({"bin": f"{edges[b]:.1f}-{edges[b + 1]:.1f}", "n": int(m.sum()),
                        "mean_predicted": float(p[m].mean()), "fraction_phishing": float(y[m].mean())})
    return out


def expected_calibration_error(y, p, bins: int = 10) -> float:
    rows = reliability_bins(y, p, bins)
    n = sum(r["n"] for r in rows)
    return float(sum(r["n"] / n * abs(r["mean_predicted"] - r["fraction_phishing"]) for r in rows)) if n else float("nan")
