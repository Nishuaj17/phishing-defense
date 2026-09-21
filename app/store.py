"""SQLite persistence. Swap for PostgreSQL when you run several workers; the interface is small.

What is stored, and what is not:
* analyses: one row per check (no message text, ever)
* incidents: an automatic record for every `block` verdict, with the evidence snapshot and
  indicators of compromise, so a human can review or share them
* feedback: "this was phishing" / "this was fine" votes from users

Privacy: submitted links can contain personal data (tokens, emails in query strings). With
store_urls=False only host names are kept and URL indicators are dropped.

Feedback is UNTRUSTED input and a data-poisoning vector (anyone can vote). It is stored for
human review and exported with `scripts/export_feedback.py`; it must never flow into training
automatically.

Upgrading from v0.1: the schema changed, so delete data/app.db (nothing in it is irreplaceable).
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    url TEXT NOT NULL,
    risk INTEGER NOT NULL,
    probability REAL NOT NULL,
    label TEXT NOT NULL,
    verified INTEGER NOT NULL,
    recommended_action TEXT NOT NULL,
    mode TEXT NOT NULL,
    stopped_at TEXT NOT NULL,
    latency_ms REAL NOT NULL,
    url_model TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analyses_ts ON analyses(ts);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    analysis_id TEXT NOT NULL,
    ts REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    severity TEXT NOT NULL,
    risk INTEGER NOT NULL,
    summary TEXT NOT NULL,
    indicators TEXT NOT NULL,
    evidence TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT NOT NULL,
    ts REAL NOT NULL,
    verdict TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_feedback_analysis ON feedback(analysis_id);
"""

MAX_FEEDBACK_PER_ANALYSIS = 3


class Store:
    def __init__(self, path: str, store_urls: bool = True):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._store_urls = store_urls
        with self._lock:
            self._db.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ------------------------------------------------------------ analyses
    def save(self, a: dict) -> None:
        if a["kind"] == "message":
            shown = "(message)"
        elif self._store_urls:
            shown = a["url"]
        else:
            shown = urlsplit(a["url"]).hostname or ""
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO analyses VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (a["id"], time.time(), a["kind"], shown[:2048], a["risk"], a["probability"], a["label"],
                 int(a["verified"]), a["recommended_action"], a["mode"], a["stopped_at"],
                 a["latency_ms"], a["versions"]["url_model"]))
            if a["recommended_action"] == "block":
                self._open_incident(a)
            self._db.commit()

    def _open_incident(self, a: dict) -> None:
        iocs = a["indicators"] if self._store_urls else [i for i in a["indicators"] if i["type"] != "url"]
        top = [e["signal"] for e in a["evidence"][:3]]
        summary = f"{a['kind'].capitalize()} blocked at risk {a['risk']}" + (f": {'; '.join(top)}" if top else "")
        self._db.execute(
            "INSERT OR REPLACE INTO incidents (id, analysis_id, ts, severity, risk, summary, indicators, evidence) "
            "VALUES (?,?,?,?,?,?,?,?)",
            ("inc-" + a["id"], a["id"], time.time(), "high" if a["risk"] >= 85 else "medium", a["risk"],
             summary, json.dumps(iocs), json.dumps(a["evidence"])))

    def recent(self, limit: int = 50) -> list[dict]:
        return self._rows("SELECT * FROM analyses ORDER BY ts DESC LIMIT ?", (self._cap(limit),))

    def stats(self) -> dict:
        with self._lock:
            total = self._db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
            by_action = dict(self._db.execute(
                "SELECT recommended_action, COUNT(*) FROM analyses GROUP BY recommended_action").fetchall())
            by_kind = dict(self._db.execute("SELECT kind, COUNT(*) FROM analyses GROUP BY kind").fetchall())
            avg_ms = self._db.execute("SELECT AVG(latency_ms) FROM analyses").fetchone()[0]
            early = self._db.execute("SELECT COUNT(*) FROM analyses WHERE stopped_at IN ('url','intel')").fetchone()[0]
            unverified = self._db.execute("SELECT COUNT(*) FROM analyses WHERE verified = 0").fetchone()[0]
            incidents = self._db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            feedback = self._db.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
        return {
            "total": total, "by_action": by_action, "by_kind": by_kind,
            "avg_latency_ms": round(avg_ms, 1) if avg_ms is not None else None,
            "decided_by_address_share": round(early / total, 3) if total else None,
            "unverified": unverified, "incidents": incidents, "feedback": feedback,
        }

    # ----------------------------------------------------------- incidents
    def incidents(self, limit: int = 50) -> list[dict]:
        rows = self._rows("SELECT * FROM incidents ORDER BY ts DESC LIMIT ?", (self._cap(limit),))
        for r in rows:
            r["indicators"] = json.loads(r["indicators"])
            r["evidence"] = json.loads(r["evidence"])
        return rows

    # ------------------------------------------------------------ feedback
    def add_feedback(self, analysis_id: str, verdict: str) -> str:
        """Return 'ok', 'unknown' (no such analysis) or 'limit' (already enough votes)."""
        with self._lock:
            if not self._db.execute("SELECT 1 FROM analyses WHERE id = ?", (analysis_id,)).fetchone():
                return "unknown"
            n = self._db.execute("SELECT COUNT(*) FROM feedback WHERE analysis_id = ?", (analysis_id,)).fetchone()[0]
            if n >= MAX_FEEDBACK_PER_ANALYSIS:
                return "limit"
            self._db.execute("INSERT INTO feedback (analysis_id, ts, verdict) VALUES (?,?,?)",
                             (analysis_id, time.time(), verdict))
            self._db.commit()
        return "ok"

    def feedback_export(self) -> list[dict]:
        """Votes joined with what the system said, for HUMAN review before any use as labels."""
        return self._rows(
            "SELECT f.id, f.ts, f.verdict AS user_verdict, a.id AS analysis_id, a.kind, a.url, a.risk, a.label, "
            "a.recommended_action FROM feedback f JOIN analyses a ON a.id = f.analysis_id ORDER BY f.ts", ())

    # ------------------------------------------------------------- helpers
    @staticmethod
    def _cap(limit: int) -> int:
        return max(1, min(limit, 500))

    def _rows(self, sql: str, params: tuple) -> list[dict]:
        with self._lock:
            cur = self._db.execute(sql, params)
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
