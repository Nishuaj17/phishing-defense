"""HTTP layer. Deliberately thin: all detection logic lives in `engine/`.

Run:  uvicorn app.main:app --reload
"""
from __future__ import annotations

import secrets
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from engine.cascade import Analyzer
from engine.fusion import LogitFusion
from engine.threatintel import LocalBlocklist, ThreatIntel
from engine.urlmodel import UrlModel

from .config import Config
from .ratelimit import TokenBucket
from .store import Store

cfg = Config.from_env()


def build_analyzer(c: Config) -> Analyzer:
    fusion = LogitFusion.load(c.fusion_path) if Path(c.fusion_path).exists() else LogitFusion()
    ti = ThreatIntel([LocalBlocklist(c.ti_list_path)] if c.ti_list_path and Path(c.ti_list_path).exists() else [])
    return Analyzer(UrlModel(c.url_model_path), t_low=c.t_low, t_high=c.t_high, fusion=fusion, ti=ti)


analyzer = build_analyzer(cfg)
store = Store(cfg.db_path, store_urls=cfg.store_urls)
limiter = TokenBucket(per_minute=cfg.rate_per_minute, burst=cfg.rate_burst)

STATIC = Path(__file__).parent / "static"

# API docs are off: Swagger UI loads scripts from a CDN, which our CSP forbids.
app = FastAPI(title="Phishing defense", version="0.2.0", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else "no-cache"
    return response


class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)
    mode: Literal["cascade", "full"] = "cascade"


class MessageRequest(BaseModel):
    text: str = Field(min_length=3, max_length=5000)
    sender: str = Field(default="", max_length=320)
    subject: str = Field(default="", max_length=300)
    mode: Literal["cascade", "full"] = "cascade"


class FeedbackRequest(BaseModel):
    analysis_id: str = Field(min_length=6, max_length=32)
    verdict: Literal["phishing", "legitimate"]


def client_ip(request: Request) -> str:
    if cfg.trust_proxy:
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def throttle(request: Request, cost: float = 1.0) -> None:
    allowed, retry_after = limiter.allow(client_ip(request), cost)
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many checks.", headers={"Retry-After": str(retry_after)})


def require_admin(token: str) -> None:
    # Disabled (404) unless PHISHDEF_ADMIN_TOKEN is set. Submitted links, incidents and votes are
    # other people's data, and usage statistics are operational detail: none belong on a public endpoint.
    if not cfg.admin_token or not secrets.compare_digest(token.encode(), cfg.admin_token.encode()):
        raise HTTPException(status_code=404, detail="Not found")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "url_model": analyzer.url_model.version,
        "kind": analyzer.url_model.kind,
        "fusion": analyzer.fusion.version,
        "modalities": {
            "url": True, "webpage": True, "text": True, "visual": False,
            "threat_intel": analyzer.ti.configured if analyzer.ti else False,
        },
    }


# Sync endpoints on purpose: FastAPI runs them in worker threads, so blocking network
# fetches do not stall the event loop.
@app.post("/api/analyze")
def analyze(req: AnalyzeRequest, request: Request):
    throttle(request)
    try:
        result = analyzer.analyze(req.url, mode=req.mode).to_dict()
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from None
    store.save(result)
    return result


@app.post("/api/analyze-message")
def analyze_message(req: MessageRequest, request: Request):
    throttle(request, cost=3)  # may open several pages
    try:
        result = analyzer.analyze_message(req.text, req.sender, req.subject, mode=req.mode).to_dict()
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from None
    store.save(result)
    return result


@app.post("/api/feedback")
def feedback(req: FeedbackRequest, request: Request):
    throttle(request)
    outcome = store.add_feedback(req.analysis_id, req.verdict)
    if outcome == "unknown":
        raise HTTPException(status_code=404, detail="We don't have a check with that ID.")
    if outcome == "limit":
        raise HTTPException(status_code=429, detail="This check already has enough feedback. Thanks!")
    return {"status": "thanks"}


@app.get("/api/stats")
def stats(x_admin_token: str = Header(default="")):
    require_admin(x_admin_token)
    return store.stats()


@app.get("/api/history")
def history(limit: int = 50, x_admin_token: str = Header(default="")):
    require_admin(x_admin_token)
    return store.recent(limit)


@app.get("/api/incidents")
def incidents(limit: int = 50, x_admin_token: str = Header(default="")):
    require_admin(x_admin_token)
    return store.incidents(limit)


@app.get("/api/feedback/export")
def feedback_export(x_admin_token: str = Header(default="")):
    require_admin(x_admin_token)
    return store.feedback_export()
