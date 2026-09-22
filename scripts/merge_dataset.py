"""Merge the daily collection files into one dataset and print the numbers you should check.
 
    python -m scripts.merge_dataset --glob "data/paired_*.jsonl" --out data/paired.jsonl --csv-out data/urls.csv
 
* Sorts by collection time (the time-based split depends on it) and drops repeated URLs
  (keeps the earliest sighting).
* Writes the full paired file (URL + HTML) and a URL-only CSV for training the Stage 1 model.
* Prints per-class counts, how many rows have HTML, and the balance of credential forms
  among pages, so login-page bias is visible before you train anything.
"""
from __future__ import annotations
 
import argparse
import csv
import glob
import hashlib
import json
from pathlib import Path
 
 
def merge(paths: list[str]) -> list[dict]:
    rows: list[dict] = []
    for p in paths:
        with open(p, encoding="utf-8") as f:
            rows += [json.loads(line) for line in f if line.strip()]
    rows.sort(key=lambda r: r["ts"])
    seen: set[str] = set()
    out = []
    for r in rows:
        if r["url"] in seen:
            continue
        seen.add(r["url"])
        out.append(r)
    return out
 
 
def summarise(rows: list[dict]) -> dict:
    from engine.pagefeatures import analyze_page
 
    def has_login(r: dict) -> bool:
        try:
            return bool(analyze_page(r["html"], r.get("final_url") or r["url"]).features["collects_credentials"])
        except ValueError:
            return False
 
    with_html = [r for r in rows if r.get("html")]
    out = {
        "rows": len(rows),
        "phishing": sum(r["label"] for r in rows),
        "benign": sum(1 - r["label"] for r in rows),
        "with_html": len(with_html),
        "phishing_with_html": sum(r["label"] for r in with_html),
        "benign_with_html": sum(1 - r["label"] for r in with_html),
    }
    # identical HTML on many domains means one phishing kit, not many independent samples
    out["phishing_distinct_html"] = len({hashlib.md5(r["html"].encode("utf-8", "replace")).hexdigest()
                                         for r in with_html if r["label"] == 1})
    for name, label in (("phishing", 1), ("benign", 0)):
        pages = [r for r in with_html if r["label"] == label]
        out[f"{name}_pages_with_login_form"] = sum(has_login(r) for r in pages)
    if rows:
        out["first_ts"], out["last_ts"] = rows[0]["ts"], rows[-1]["ts"]
        out["days_spanned"] = round((rows[-1]["ts"] - rows[0]["ts"]) / 86400, 1)
    return out
 
 
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--glob", default="data/paired_*.jsonl")
    ap.add_argument("--out", default="data/paired.jsonl")
    ap.add_argument("--csv-out", default="data/urls.csv")
    a = ap.parse_args()
 
    paths = sorted(p for p in glob.glob(a.glob) if Path(p).resolve() != Path(a.out).resolve())
    if not paths:
        raise SystemExit(f"No files match {a.glob}")
    rows = merge(paths)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    with open(a.csv_out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label", "ts"])
        w.writerows((r["url"], r["label"], r["ts"]) for r in rows)
    print(f"Merged {len(paths)} files -> {a.out}, {a.csv_out}")
    for k, v in summarise(rows).items():
        print(f"  {k}: {v}")
 
 
if __name__ == "__main__":
    main()
 
