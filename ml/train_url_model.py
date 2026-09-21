"""Train the Stage 1 URL model.

Input CSV columns: url, label (1 = phishing, 0 = legitimate), and optionally ts
(unix seconds when the URL was observed).

If `ts` is present the split is by time (oldest 80% train, newest 20% test), which
is the honest setup: phishing campaigns change, and a random split lets near-duplicate
URLs from the same campaign leak into the test set. Without `ts` you get a stratified
random split and a warning.

Usage:
    python -m ml.train_url_model --csv data/urls.csv --out models/url_v1.joblib --version url-gbm-v1
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (average_precision_score, brier_score_loss, f1_score, precision_score, recall_score,
                             roc_auc_score, roc_curve)
from sklearn.model_selection import train_test_split

from engine.urlfeatures import FEATURE_NAMES, feature_vector
from ml.calibration import expected_calibration_error


def tpr_at_fpr(y, p, target: float = 0.01) -> float:
    fpr, tpr, _ = roc_curve(y, p)
    ok = tpr[fpr <= target]
    return float(ok.max()) if len(ok) else 0.0


def metrics(y, p, thr: float = 0.5) -> dict:
    pred = (p >= thr).astype(int)
    neg = (y == 0).sum()
    return {
        "n": int(len(y)),
        "positives": int(y.sum()),
        "roc_auc": float(roc_auc_score(y, p)),
        "pr_auc": float(average_precision_score(y, p)),
        "brier": float(brier_score_loss(y, p)),
        "ece": expected_calibration_error(y, p),
        "precision@0.5": float(precision_score(y, pred, zero_division=0)),
        "recall@0.5": float(recall_score(y, pred)),
        "f1@0.5": float(f1_score(y, pred)),
        "fpr@0.5": float(((pred == 1) & (y == 0)).sum() / neg) if neg else float("nan"),
        "tpr@1%fpr": tpr_at_fpr(y, p, 0.01),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--out", default="models/url_v1.joblib")
    ap.add_argument("--version", default="url-gbm-v1")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()

    df = pd.read_csv(a.csv).dropna(subset=["url", "label"]).drop_duplicates(subset=["url"])
    X, keep = [], []
    for i, u in enumerate(df["url"].astype(str)):
        try:
            X.append(feature_vector(u))
            keep.append(i)
        except ValueError:
            continue  # unparseable URL
    df = df.iloc[keep].reset_index(drop=True)
    X = np.array(X, dtype=float)
    y = df["label"].astype(int).to_numpy()
    print(f"{len(y)} usable rows, {int(y.sum())} phishing ({y.mean():.1%})")

    split_ts = None
    split = "random"
    if "ts" in df.columns:
        ts = df["ts"].to_numpy(dtype=float)
        cand = float(np.sort(ts)[int(len(ts) * 0.8)])
        tr, te = np.where(ts < cand)[0], np.where(ts >= cand)[0]
        if len(tr) and len(te):
            split, split_ts = "time", cand
    if split == "random":
        print("WARNING: no usable 'ts' column, using a random split. Expect optimistic numbers.")
        tr, te = train_test_split(np.arange(len(y)), test_size=0.2, stratify=y, random_state=a.seed)

    model = HistGradientBoostingClassifier(max_depth=6, learning_rate=0.1, max_iter=200, random_state=a.seed)
    model.fit(X[tr], y[tr])
    m = metrics(y[te], model.predict_proba(X[te])[:, 1])
    print(f"{split} split, test metrics:\n{json.dumps(m, indent=2)}")

    benign_train = X[tr][y[tr] == 0]
    bundle = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "medians": np.median(benign_train, axis=0).tolist(),  # baseline for occlusion explanations
        "version": a.version,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "split": split,
        "split_ts": split_ts,  # experiments/evaluate.py evaluates only on rows at or after this time
        "metrics": m,
    }
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, out)
    out.with_suffix(".metrics.json").write_text(json.dumps({k: v for k, v in bundle.items() if k not in ("model", "medians")}, indent=2))
    print(f"Saved {out}")


if __name__ == "__main__":
    main()
