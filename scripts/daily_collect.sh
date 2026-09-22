#!/usr/bin/env bash
# One day of data collection. Run it ONCE a day from the project root, on an isolated machine:
#   bash scripts/daily_collect.sh
# It downloads today's phishing feed, takes a fresh slice of benign domains, fetches everything,
# and writes data/paired_<date>.jsonl. URLs seen on earlier days are skipped.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p feeds data
 
TODAY=$(date +%F)
OUT="data/paired_${TODAY}.jsonl"
if [ -e "$OUT" ]; then
  echo "Already collected today ($OUT exists). Run again tomorrow."
  exit 0
fi
 
DAY_FILE=data/.day
DAY=$(cat "$DAY_FILE" 2>/dev/null || echo 0)
PER_DAY=300
 
# Benign domains: a fixed random sample from the top 100k, not the top 10k in order.
# Phishing hosts are mostly unranked, so a top-only benign set would teach the model "popular = safe".
if [ ! -s feeds/tranco_100k_shuffled.csv ]; then
  if [ ! -s feeds/top-1m.csv ]; then
    echo "Downloading the Tranco list..."
    curl -sfL https://tranco-list.eu/top-1m.csv.zip -o feeds/tranco.zip
    unzip -o -q feeds/tranco.zip -d feeds
  fi
  python - <<'PY'
import random
rows = open("feeds/top-1m.csv", encoding="utf-8").read().splitlines()[:100000]
random.Random(7).shuffle(rows)
open("feeds/tranco_100k_shuffled.csv", "w", encoding="utf-8").write("\n".join(rows) + "\n")
PY
fi
 
echo "Downloading today's phishing feed..."
curl -sfL https://openphish.com/feed.txt -o "feeds/phish_${TODAY}.txt"
echo "Feed lines: $(wc -l < "feeds/phish_${TODAY}.txt")"
 
python -m scripts.collect_dataset \
  --phish "feeds/phish_${TODAY}.txt" \
  --benign feeds/tranco_100k_shuffled.csv --benign-offset $((DAY * PER_DAY)) --n-benign "$PER_DAY" \
  --n-phish 300 \
  --out "$OUT" --csv-out "data/urls_${TODAY}.csv"
 
echo $((DAY + 1)) > "$DAY_FILE"
echo "Day $((DAY + 1)) done. Run again tomorrow."
 
