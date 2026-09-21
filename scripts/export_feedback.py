"""Export user feedback for HUMAN REVIEW. This is the "learn" step of the defense lifecycle.

    python -m scripts.export_feedback --db data/app.db --out data/feedback_review.jsonl --disagreements-only

Each row pairs a user's vote with what the system said. Nothing here is a trusted label:
anyone can vote, so votes are a data-poisoning vector (the same attack class your paper studies).
Suggested workflow: review the disagreements, verify each URL against independent sources,
then add confirmed samples to your next dataset collection with a fresh timestamp. Never point
training at this file directly.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.store import Store


def disagrees(row: dict) -> bool:
    said_phish = row["recommended_action"] in ("block", "warn")
    user_phish = row["user_verdict"] == "phishing"
    return said_phish != user_phish


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="data/app.db")
    ap.add_argument("--out", default="data/feedback_review.jsonl")
    ap.add_argument("--disagreements-only", action="store_true")
    a = ap.parse_args()

    store = Store(a.db)
    rows = store.feedback_export()
    store.close()
    if a.disagreements_only:
        rows = [r for r in rows if disagrees(r)]
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"Wrote {len(rows)} rows for review -> {a.out} (not trusted labels)")


if __name__ == "__main__":
    main()
