"""Fit the learned fusion (and, as a side effect, calibrate it) on the VALIDATION half of the
held-out rows, never on the rows the URL model trained on and never on the test half.

    python -m experiments.fit_fusion --data data/paired.jsonl --url-model models/url_v1.joblib \\
        --out models/fusion_v1.json

Then evaluate on the untouched test half:

    python -m experiments.evaluate --data data/paired.jsonl --url-model models/url_v1.joblib \\
        --fusion models/fusion_v1.json --sweep

The fitted model is logistic regression on [logit p_url, logit p_page], so the output is a
Platt-style calibrated probability for the validation slice's phishing share. If your
production traffic has a very different share, say so before calling it a probability.
"""
from __future__ import annotations

import argparse

from engine.urlmodel import UrlModel
from experiments.evaluate import fit_fusion_on, load_jsonl, select_heldout_rows, split_val_test


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", required=True)
    ap.add_argument("--url-model", default=None)
    ap.add_argument("--out", default="models/fusion_v1.json")
    ap.add_argument("--holdout", type=float, default=0.2)
    ap.add_argument("--C", type=float, default=1.0, help="inverse L2 regularisation strength")
    a = ap.parse_args()

    model = UrlModel(a.url_model)
    heldout, note = select_heldout_rows(load_jsonl(a.data), model, a.holdout)
    val, test = split_val_test(heldout)
    print(f"Held-out rows: {len(heldout)} ({note}). Validation: {len(val)} (fit here). Test: {len(test)} (untouched).")
    fusion = fit_fusion_on(val, model, C=a.C)
    fusion.save(a.out)
    print(f"Learned weights: {fusion.weights}, intercept {fusion.bias:.3f}")
    print(f"Saved {a.out}. Now run experiments.evaluate with --fusion {a.out} to score the test half.")


if __name__ == "__main__":
    main()
