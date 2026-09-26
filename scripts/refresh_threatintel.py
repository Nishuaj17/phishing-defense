"""Refresh the local threat-intel blocklist from URLhaus's free, no-key-required feed.

URLhaus (abuse.ch) publishes a plain-text list of currently active malicious URLs, one per
line. It happens to be exactly the format `engine.threatintel.LocalBlocklist` already reads
(comment lines start with '#', full URLs match exactly), so no new provider code is needed:
this script only refreshes the file that `PHISHDEF_TI_LIST` points at.

Run it periodically (daily is plenty; URLhaus updates continuously but the "online" list only
matters at the granularity of your analyze requests) - by hand, via cron, or alongside
scripts/daily_collect.sh. It never runs during a request: threat-intel lookups must be fast and
this keeps them a simple file read (see engine/threatintel.py).

Usage:
    python -m scripts.refresh_threatintel --out data/threatintel/urlhaus.txt

Safety: written atomically (temp file + rename), so a crash mid-download never leaves a partial
file. If the download fails or looks wrong (too small, no header), the existing file is left
untouched and the exit code is non-zero - failing with the OLD list still protecting you is far
safer than silently switching to an empty one.
"""
from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Callable

import requests

URLHAUS_ONLINE_FEED = "https://urlhaus.abuse.ch/downloads/text_online/"
MIN_LINES = 20  # a healthy feed normally has hundreds to thousands; this only catches empty/broken downloads


def default_fetch(url: str) -> str:
    r = requests.get(url, timeout=30, headers={"User-Agent": "PhishDefenseResearchBot/0.1"})
    r.raise_for_status()
    return r.text


def looks_healthy(text: str) -> bool:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    urls = [ln for ln in lines if not ln.startswith("#")]
    return len(urls) >= MIN_LINES


def refresh(out_path: str, url: str = URLHAUS_ONLINE_FEED, fetch: Callable[[str], str] = default_fetch) -> tuple[bool, str]:
    """Return (ok, message). On failure the file at out_path (if any) is left untouched."""
    try:
        text = fetch(url)
    except requests.RequestException as e:
        return False, f"Download failed ({type(e).__name__}): {e}"
    if not looks_healthy(text):
        return False, f"Downloaded feed looks empty or broken ({len(text.splitlines())} lines); kept the existing list."

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=out.parent, prefix=".urlhaus-", suffix=".tmp")
    try:
        with open(fd, "w", encoding="utf-8") as f:
            f.write(f"# URLhaus online malicious URLs, refreshed by scripts/refresh_threatintel.py\n")
            f.write(f"# Source: {url}\n")
            f.write(text if text.endswith("\n") else text + "\n")
        Path(tmp).replace(out)  # atomic on the same filesystem
    finally:
        Path(tmp).unlink(missing_ok=True)
    n = sum(1 for ln in text.splitlines() if ln.strip() and not ln.startswith("#"))
    return True, f"Saved {n} indicators -> {out_path}"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="data/threatintel/urlhaus.txt")
    ap.add_argument("--url", default=URLHAUS_ONLINE_FEED)
    a = ap.parse_args()
    ok, msg = refresh(a.out, a.url)
    print(msg)
    if not ok:
        sys.exit(1)
    print(f"Set PHISHDEF_TI_LIST={a.out} when starting the server to use it.")


if __name__ == "__main__":
    main()
