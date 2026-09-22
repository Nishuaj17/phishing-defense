"""Print random samples so you can check labels by eye. Do this before training.
 
    python -m scripts.inspect_samples --data data/paired.jsonl --label 1 -n 25
 
Labels come from a feed at listing time, but the page is fetched later. By then a phishing
page may be taken down, replaced by a parked page, or redirected to the real brand. Such rows
are label noise. Look for: a phishing row that lands on a blank/parked/legitimate page, and a
benign row that is an error page or a login wall. Write down the share you had to discard and
report it in the paper's data section.
"""
from __future__ import annotations
 
import argparse
import json
import random
import re
 
from bs4 import BeautifulSoup
 
from engine.pagefeatures import analyze_page
from engine.urlfeatures import parse_url
 
 
def describe(r: dict) -> dict:
    soup = BeautifulSoup(r["html"], "lxml")
    title = soup.title.get_text(" ", strip=True)[:90] if soup.title else ""
    for t in soup(["script", "style", "noscript"]):
        t.decompose()
    snippet = re.sub(r"\s+", " ", soup.get_text(" ", strip=True))[:160]
    landed = r.get("final_url") or r["url"]
    try:
        moved = parse_url(landed).reg_domain != parse_url(r["url"]).reg_domain
        f = analyze_page(r["html"], landed).features
    except ValueError:
        moved, f = False, {}
    return {
        "url": r["url"], "landed_on": landed, "moved_to_other_domain": moved, "status": r.get("status"),
        "title": title, "login_form": bool(f.get("collects_credentials")),
        "form_sends_elsewhere": bool(f.get("ext_form_action")), "text": snippet, "html_bytes": len(r["html"]),
    }
 
 
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", required=True)
    ap.add_argument("--label", choices=["0", "1", "any"], default="any")
    ap.add_argument("-n", type=int, default=20)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
 
    with open(a.data, encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]
    rows = [r for r in rows if r.get("html") and (a.label == "any" or r["label"] == int(a.label))]
    random.Random(a.seed).shuffle(rows)
    for i, r in enumerate(rows[: a.n], 1):
        d = describe(r)
        print(f"--- {i}. label={'phishing' if r['label'] else 'benign'}")
        for k, v in d.items():
            print(f"  {k}: {v}")
    print(f"\nShowed {min(a.n, len(rows))} of {len(rows)} matching rows.")
 
 
if __name__ == "__main__":
    main()
 
