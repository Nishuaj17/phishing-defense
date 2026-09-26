#!/bin/sh
set -eu

echo "Refreshing URLhaus threat-intelligence feed..."

if python -m scripts.refresh_threatintel --out data/threatintel/urlhaus.txt; then
    export PHISHDEF_TI_LIST="data/threatintel/urlhaus.txt"
    echo "URLhaus threat-intelligence feed configured."
else
    echo "WARNING: URLhaus refresh failed; starting without a refreshed feed."
fi

exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
