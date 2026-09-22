"""Build the paired dataset: for every URL, fetch the page NOW and store its HTML.
 
Why this matters: phishing pages are usually taken down within hours, so a URL list
alone cannot be turned into a multimodal dataset later. Capture the page at collection
time, together with a timestamp for time-based splits.
 
Sources (you provide them; check each feed's terms of use before collecting or sharing data):
  --phish   a text file or http(s) URL with one phishing URL per line (e.g. the OpenPhish or URLhaus feeds)
  --benign  a Tranco-style CSV (rank,domain) or a text file of domains/URLs
 
Benign-set pitfall: if every benign sample is a homepage and every phishing sample is a
login page, the model just learns "login form = phishing". Collect legitimate login pages
too: the default --benign-paths fetches both "/" and "/login" for every domain.
 
Safety: run this on an isolated VM, never in your normal browser. Fetching goes through
engine.fetcher, which blocks internal addresses and never executes JavaScript.
 
Usage:
  python -m scripts.collect_dataset --phish feeds/phish.txt --benign feeds/tranco.csv \\
      --n-phish 500 --n-benign 500 --out data/paired.jsonl --csv-out data/urls.csv
"""
from __future__ import annotations
 
import argparse
import csv
import json
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Iterable
 
import requests
 
from engine.fetcher import FetchResult, fetch_page
 
 
def read_source(src: str) -> list[str]:
    if src.startswith(("http://", "https://")):
        r = requests.get(src, timeout=30, headers={"User-Agent": "PhishDefenseResearchBot/0.1"})
        r.raise_for_status()
        text = r.text
    else:
        text = Path(src).read_text(encoding="utf-8", errors="replace")
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
 
 
def valid_urls(lines: Iterable[str]) -> list[str]:
    """Keep only real http(s) URLs, once each. A download that saved an HTML error page or a
    redirect notice must not silently become "phishing samples"."""
    seen: dict[str, str] = {}
    for ln in lines:
        if re.match(r"^https?://\S+$", ln, re.I):
            seen.setdefault(ln, ln)
    return list(seen)
 
 
def refuse_overwrite(*paths: str, overwrite: bool = False) -> None:
    """Stop before fetching anything if an output file already exists. Collected pages cannot be
    re-fetched later (phishing pages die within hours), so silently replacing a file is data loss."""
    if overwrite:
        return
    existing = [p for p in paths if Path(p).exists()]
    if existing:
        raise SystemExit(f"{', '.join(existing)} already exists, so nothing was fetched. "
                         "Use a different --out/--csv-out name, or pass --overwrite if you really mean to replace it.")
 
 
def load_seen(path: str) -> set[str]:
    p = Path(path)
    return set(p.read_text(encoding="utf-8").split()) if p.exists() else set()
 
 
def benign_urls(lines: Iterable[str], paths: list[str]) -> list[str]:
    urls = []
    for ln in lines:
        item = ln.split(",")[-1].strip()  # Tranco rows are "rank,domain"
        if not item:
            continue
        base = item if "://" in item else f"https://{item}"
        base = base.rstrip("/")
        for p in paths:
            urls.append(base + (p if p != "/" else "/"))
    return urls
 
 
def collect(items: list[tuple[str, int]], fetch: Callable[[str], FetchResult] = fetch_page,
            workers: int = 8) -> list[dict]:
    def one(item: tuple[str, int]) -> dict:
        url, label = item
        fr = fetch(url)
        # Only a 2xx page counts. A 404 or 403 error page is HTML too, but storing it would put
        # "page not found" screens in the dataset labelled as real benign or phishing pages.
        ok = bool(fr.ok and fr.status is not None and 200 <= fr.status < 300)
        return {
            "url": url,
            "label": label,
            "ts": time.time(),  # collection time; prefer the feed's first-seen time if you have it
            "fetch_ok": ok,
            "status": fr.status,
            "final_url": fr.final_url,
            "fetch_ms": round(fr.ms, 1),
            "error": fr.error or ("" if ok else f"HTTP {fr.status}"),
            "html": fr.html if ok else "",
        }
 
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(one, items))
 
 
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--phish", required=True)
    ap.add_argument("--benign", required=True)
    ap.add_argument("--n-phish", type=int, default=500)
    ap.add_argument("--n-benign", type=int, default=500, help="benign domains to use (each yields one URL per path)")
    ap.add_argument("--benign-paths", default="/,/login")
    ap.add_argument("--benign-offset", type=int, default=0, help="skip this many benign domains, so each day uses a fresh slice")
    ap.add_argument("--seen", default="data/seen_urls.txt", help="URLs collected on earlier runs are skipped, then added here")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default="data/paired.jsonl")
    ap.add_argument("--csv-out", default="data/urls.csv")
    ap.add_argument("--overwrite", action="store_true", help="replace existing output files (normally refused)")
    a = ap.parse_args()
    refuse_overwrite(a.out, a.csv_out, overwrite=a.overwrite)
 
    rng = random.Random(a.seed)
    raw = read_source(a.phish)
    phish = valid_urls(raw)
    if len(phish) < len(raw):
        print(f"WARNING: ignored {len(raw) - len(phish)} of {len(raw)} lines in {a.phish} that are not http(s) URLs or are duplicates.")
    if not phish:
        raise SystemExit(f"No valid URLs found in {a.phish}. If you used curl, add -L to follow redirects, then check the file with head.")
    seen = load_seen(a.seen)
    phish = [u for u in phish if u not in seen]
    print(f"{len(phish)} phishing URLs are new (not collected on an earlier run).")
    rng.shuffle(phish)
    domains = read_source(a.benign)[a.benign_offset: a.benign_offset + a.n_benign]
    benign = [u for u in benign_urls(domains, a.benign_paths.split(",")) if u not in seen]
    items = [(u, 1) for u in phish[: a.n_phish]] + [(u, 0) for u in benign]
    print(f"Fetching {len(items)} URLs ({min(len(phish), a.n_phish)} phishing, {len(benign)} benign)...")
    rows = collect(items, workers=a.workers)
    rows.sort(key=lambda r: r["ts"])
 
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    with open(a.csv_out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label", "ts"])
        w.writerows((r["url"], r["label"], r["ts"]) for r in rows)
    Path(a.seen).parent.mkdir(parents=True, exist_ok=True)
    with open(a.seen, "a", encoding="utf-8") as f:
        f.writelines(r["url"] + "\n" for r in rows)
    ok = sum(r["fetch_ok"] for r in rows)
    print(f"Saved {len(rows)} rows ({ok} with page HTML) -> {a.out}, {a.csv_out}")
 
 
if __name__ == "__main__":
    main()
 
