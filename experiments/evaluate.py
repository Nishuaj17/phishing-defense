"""Offline evaluation over a paired dataset (url + saved html + label).

Runs the paper's core comparison on the *same* held-out samples:

    URL only | page only | fused (default weights) | fused (learned) | cascade

plus a sweep over the cascade thresholds (t_low, t_high), which traces the accuracy /
escalation-rate / latency trade-off, and calibration diagnostics (Brier score, ECE).

Input JSONL, one object per line:
    {"url": "...", "label": 1, "html": "<html>...", "ts": 1712345678, "fetch_ms": 420}
`fetch_ms` is optional (measured by scripts/collect_dataset.py); otherwise --fetch-ms is assumed.
Rows whose page could not be fetched (empty html) are excluded so every method sees identical samples.

Data roles (never mix them):
    train     rows with ts <  the URL model's split boundary    -> fits the URL model
    validate  older half of the held-out rows                   -> fits the learned fusion
    test      newer half of the held-out rows                   -> reported numbers
Without --fusion there is nothing to fit on the held-out rows, so the whole held-out region is
the test set. With --fusion only the test half is scored, so all methods stay comparable.

Threat intelligence is deliberately NOT used here (see engine/threatintel.py).

Usage:
    python -m experiments.evaluate --data data/paired.jsonl --url-model models/url_v1.joblib \\
        --fusion models/fusion_v1.json --sweep
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np

from engine.cascade import stage1_decision
from engine.fusion import LogitFusion
from engine.pagefeatures import analyze_page
from engine.urlmodel import UrlModel
from ml.calibration import expected_calibration_error, reliability_bins
from ml.train_url_model import metrics


def load_jsonl(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def select_heldout_rows(rows: list[dict], model: UrlModel, holdout: float) -> tuple[list[dict], str]:
    rows = [r for r in rows if r.get("html")]
    if model.split_ts is not None:
        return [r for r in rows if r.get("ts", 0) >= model.split_ts], f"ts >= {model.split_ts:.0f} (model's training boundary)"
    if rows and all("ts" in r for r in rows):
        rows = sorted(rows, key=lambda r: r["ts"])
        return rows[int(len(rows) * (1 - holdout)):], f"newest {holdout:.0%} by ts"
    return rows, "all rows (no ts available: results may be optimistic)"


# kept for callers that only need the held-out region
select_test_rows = select_heldout_rows


def split_val_test(heldout: list[dict]) -> tuple[list[dict], list[dict]]:
    """Older half validates (fits fusion), newer half tests. Sorted by time, never shuffled."""
    ordered = sorted(heldout, key=lambda r: r.get("ts", 0))
    cut = len(ordered) // 2
    return ordered[:cut], ordered[cut:]


def score_rows(rows: list[dict], model: UrlModel, fetch_ms: float) -> dict:
    y, p1, p2, c1, c2 = [], [], [], [], []
    for r in rows:
        t0 = time.perf_counter()
        s1 = model.predict(r["url"]).score
        t1 = time.perf_counter()
        s2 = analyze_page(r["html"], r.get("final_url") or r["url"]).score
        t2 = time.perf_counter()
        y.append(int(r["label"]))
        p1.append(s1)
        p2.append(s2)
        c1.append((t1 - t0) * 1000)
        c2.append((t2 - t1) * 1000 + float(r.get("fetch_ms", fetch_ms)))
    return {"y": np.array(y), "p1": np.array(p1), "p2": np.array(p2), "c1": np.array(c1), "c2": np.array(c2)}


def fuse_all(d: dict, fusion: LogitFusion) -> np.ndarray:
    return np.array([fusion.predict({"url": a, "page": b}) for a, b in zip(d["p1"], d["p2"])])


def fit_fusion_on(rows: list[dict], model: UrlModel, fetch_ms: float = 600.0, C: float = 1.0) -> LogitFusion:
    d = score_rows(rows, model, fetch_ms)
    if len(set(d["y"])) < 2:
        raise ValueError("The validation slice needs both classes to fit fusion.")
    ts = [r.get("ts", 0) for r in rows]
    meta = {"n_validation": int(len(d["y"])), "phishing_share": float(d["y"].mean()),
            "ts_range": [min(ts), max(ts)], "url_model": model.version}
    pairs = [{"url": float(a), "page": float(b)} for a, b in zip(d["p1"], d["p2"])]
    return LogitFusion.fit(pairs, d["y"], version="logit-fit-v1", C=C, meta=meta)


def cascade_point(d: dict, fused: np.ndarray, t_low: float, t_high: float) -> dict:
    stop = np.array([stage1_decision(p, t_low, t_high) != "escalate" for p in d["p1"]])
    final = np.where(stop, d["p1"], fused)
    m = metrics(d["y"], final)
    m.update({"t_low": t_low, "t_high": t_high, "escalation_rate": float((~stop).mean()),
              "mean_cost_ms": float(np.mean(d["c1"] + np.where(stop, 0.0, d["c2"])))})
    m["_final"] = final  # stripped before saving
    return m


def evaluate(rows: list[dict], model: UrlModel, t_low: float, t_high: float, sweep: bool = False,
             fusion: LogitFusion | None = None, fetch_ms: float = 600.0) -> dict:
    d = score_rows(rows, model, fetch_ms)
    if len(set(d["y"])) < 2:
        raise ValueError("The test set needs both classes to compute ROC metrics.")
    default = LogitFusion()
    active = fusion or default
    fused_default, fused_active = fuse_all(d, default), fuse_all(d, active)
    casc = cascade_point(d, fused_active, t_low, t_high)
    final = casc.pop("_final")

    out = {
        "n_test": int(len(d["y"])),
        "url_only": {**metrics(d["y"], d["p1"]), "mean_cost_ms": float(d["c1"].mean())},
        "page_only": {**metrics(d["y"], d["p2"]), "mean_cost_ms": float(d["c2"].mean())},
        "fused_default": {**metrics(d["y"], fused_default), "mean_cost_ms": float((d["c1"] + d["c2"]).mean())},
        "cascade": casc,
        "fusion_used": active.version,
    }
    if fusion is not None:
        out["fused_learned"] = {**metrics(d["y"], fused_active), "mean_cost_ms": float((d["c1"] + d["c2"]).mean())}
    out["calibration"] = {
        "cascade": {"ece": expected_calibration_error(d["y"], final), "bins": reliability_bins(d["y"], final)},
        "fused": {"ece": expected_calibration_error(d["y"], fused_active), "bins": reliability_bins(d["y"], fused_active)},
    }
    if sweep:
        pts = [cascade_point(d, fused_active, lo, hi) for lo in (0.03, 0.06, 0.1, 0.15, 0.25) for hi in (0.8, 0.9, 0.95, 0.99)]
        for p in pts:
            p.pop("_final")
        out["sweep"] = pts
    return out


def _row(name: str, m: dict) -> str:
    return (f"{name:<16}{m['roc_auc']:>7.3f}{m['tpr@1%fpr']:>10.3f}{m['precision@0.5']:>7.3f}"
            f"{m['recall@0.5']:>8.3f}{m['fpr@0.5']:>7.3f}{m['brier']:>8.3f}{m['mean_cost_ms']:>10.1f}")


def print_report(res: dict, note: str) -> None:
    print(f"\nTest samples: {res['n_test']}  ({note})")
    print(f"{'method':<16}{'AUC':>7}{'TPR@1%FPR':>10}{'prec':>7}{'recall':>8}{'FPR':>7}{'Brier':>8}{'cost ms':>10}")
    keys = [("url_only", "URL only"), ("page_only", "Page only"), ("fused_default", "Fused (default)")]
    if "fused_learned" in res:
        keys.append(("fused_learned", "Fused (learned)"))
    keys.append(("cascade", "Cascade"))
    for key, name in keys:
        print(_row(name, res[key]))
    c = res["cascade"]
    print(f"\nCascade uses fusion '{res['fusion_used']}' at t_low={c['t_low']}, t_high={c['t_high']}: "
          f"page opened for {c['escalation_rate']:.1%} of links")
    print(f"ECE (lower is better calibrated): cascade {res['calibration']['cascade']['ece']:.3f}, "
          f"fused {res['calibration']['fused']['ece']:.3f}")
    if "sweep" in res:
        print(f"\n{'t_low':>6}{'t_high':>8}{'escalated':>11}{'AUC':>8}{'TPR@1%FPR':>11}{'recall':>8}{'FPR':>8}{'cost ms':>10}")
        for s in res["sweep"]:
            print(f"{s['t_low']:>6}{s['t_high']:>8}{s['escalation_rate']:>11.1%}{s['roc_auc']:>8.3f}"
                  f"{s['tpr@1%fpr']:>11.3f}{s['recall@0.5']:>8.3f}{s['fpr@0.5']:>8.3f}{s['mean_cost_ms']:>10.1f}")
    print("\nPage-stage cost includes fetch time (measured per row if 'fetch_ms' is present, else assumed).")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", required=True)
    ap.add_argument("--url-model", default=None, help="joblib bundle; omit to evaluate the heuristic baseline")
    ap.add_argument("--fusion", default=None, help="fusion JSON from experiments.fit_fusion; scores the test half only")
    ap.add_argument("--t-low", type=float, default=0.06)
    ap.add_argument("--t-high", type=float, default=0.93)
    ap.add_argument("--holdout", type=float, default=0.2)
    ap.add_argument("--fetch-ms", type=float, default=600.0)
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--out", default="results/evaluation.json")
    a = ap.parse_args()

    model = UrlModel(a.url_model)
    heldout, note = select_heldout_rows(load_jsonl(a.data), model, a.holdout)
    fusion = LogitFusion.load(a.fusion) if a.fusion else None
    if fusion is not None:
        _, heldout = split_val_test(heldout)
        note += "; newer half only, the older half was used to fit fusion"
    res = evaluate(heldout, model, a.t_low, a.t_high, a.sweep, fusion=fusion, fetch_ms=a.fetch_ms)
    res["url_model"] = model.version
    res["holdout_rule"] = note
    print_report(res, note)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=2))
    print(f"Saved {a.out}")


if __name__ == "__main__":
    main()
